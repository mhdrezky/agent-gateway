"""Read-only SQL gate (PostgreSQL dialect), ported from the agentgate doorman.

Free SQL from an agent passes here before it reaches a database. The table
allow-list cannot be enforced in a prompt, so it is enforced on the parsed tree:

  * exactly one statement, and it is a read query (SELECT or a set operation);
  * no write, DDL, command, or SELECT INTO node anywhere, subqueries and CTEs included;
  * no function that reaches files, other servers, or server state;
  * every real table is in the allowed set and in the resource's schema,
    and is rewritten to `<schema>.<table>` so resolution cannot be redirected;
  * a row cap: the query is wrapped so at most cap + 1 rows come back.

The database session is read-only too. This gate is the first wall, not the only one.
"""

from dataclasses import dataclass

from sqlglot import exp, parse, to_identifier
from sqlglot.errors import SqlglotError

from agent_gateway.brokers.output import BrokerError

DIALECT = "postgres"

# Node types that must never appear, looked up by name so a sqlglot release that
# renames or drops one does not break the import.
_FORBIDDEN = tuple(
    getattr(exp, n)
    for n in (
        "Insert", "Update", "Delete", "Merge", "Drop", "Create", "Alter", "TruncateTable",
        "Command", "Set", "SetItem", "Use", "Transaction", "Commit", "Rollback", "Grant",
        "Revoke", "Pragma", "Copy", "Into", "Lock", "Analyze", "Refresh", "Call",
    )
    if hasattr(exp, n)
)  # fmt: skip

# PostgreSQL functions that read files, reach other servers, sleep, or change state.
_BANNED_FUNCS = frozenset(
    {
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
        "lo_import", "lo_export", "lo_get", "lo_put",
        "dblink", "dblink_exec", "dblink_connect",
        "pg_sleep", "pg_sleep_for", "pg_sleep_until",
        "set_config", "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
        "query_to_xml", "query_to_json", "pg_execute_server_program",
    }
)  # fmt: skip

# How many allowed tables to list in a denial before "(+N more)".
_MAX_ALLOWED_LISTED = 60


class SqlDeniedError(BrokerError):
    """The query breaks the gate's policy. The message is safe to show the agent."""


@dataclass(frozen=True, slots=True)
class GatedQuery:
    sql: str
    tables: frozenset[str]
    cap: int


def parse_one(sql: str) -> exp.Expr:
    try:
        statements = [s for s in parse(sql, read=DIALECT) if s is not None]
    except SqlglotError as exc:
        raise SqlDeniedError(f"could not parse SQL ({type(exc).__name__})") from exc
    if not statements:
        raise SqlDeniedError("empty query")
    if len(statements) > 1:
        raise SqlDeniedError("only a single statement is allowed")
    return statements[0]


def _out_of_scope_msg(denied: list[str], allowed: frozenset[str]) -> str:
    """Names every out-of-scope table and lists what the agent may query. The allowed
    set is the resource's own scope, so listing it leaks nothing across grants."""
    noun = "table" if len(denied) == 1 else "tables"
    bad = ", ".join(f"'{d}'" for d in denied)
    if not allowed:
        return f"{noun} {bad} not in your allowed set — you have no tables granted"
    names = sorted(allowed)
    shown = ", ".join(names[:_MAX_ALLOWED_LISTED])
    more = len(names) - _MAX_ALLOWED_LISTED
    if more > 0:
        shown += f", (+{more} more)"
    return (
        f"{noun} {bad} not in your allowed set. Tables you can query: {shown}. "
        "Use only these — do not query, join, or reference any other table."
    )


def validate_and_scope(stmt: exp.Expr, schema: str, allowed: frozenset[str]) -> set[str]:
    """Enforce the policy and pin every table to `schema`. Mutates `stmt` in place.
    Returns the referenced table names (lowercase)."""
    if not isinstance(stmt, exp.Query):
        raise SqlDeniedError("only read-only SELECT queries are allowed")
    if _FORBIDDEN and next(stmt.find_all(*_FORBIDDEN), None) is not None:
        raise SqlDeniedError("only read-only SELECT queries are allowed")
    for fn in stmt.find_all(exp.Func):
        name = (fn.name if isinstance(fn, exp.Anonymous) else fn.sql_name()).lower()
        if name in _BANNED_FUNCS:
            raise SqlDeniedError(f"function '{name}' is not allowed")

    cte_names = {c.alias_or_name.lower() for c in stmt.find_all(exp.CTE)}
    referenced: set[str] = set()
    out_of_scope: list[str] = []
    for table in stmt.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            raise SqlDeniedError("unsupported table expression")
        name = table.name.lower()
        if name in cte_names and not table.db:
            continue
        if table.catalog:
            raise SqlDeniedError("cross-database references are not allowed")
        if table.db and table.db.lower() != schema:
            raise SqlDeniedError(f"schema '{table.db}' is not allowed")
        if name not in allowed:
            if name not in out_of_scope:
                out_of_scope.append(name)
            continue
        referenced.add(name)
        table.set("db", to_identifier(schema))
        table.set("catalog", None)

    if out_of_scope:
        raise SqlDeniedError(_out_of_scope_msg(out_of_scope, allowed))
    if not referenced:
        raise SqlDeniedError("query references no allowed tables")
    return referenced


def apply_cap(stmt: exp.Expr, cap: int) -> exp.Expr:
    """Wrap the query so at most cap + 1 rows come back. The extra row tells the
    caller there was more; it is dropped before the rows are returned."""
    if not isinstance(stmt, exp.Query):
        raise SqlDeniedError("only read-only SELECT queries are allowed")
    return exp.select("*").from_(stmt.subquery("q")).limit(cap + 1)


def gate(sql: str, schema: str, allowed: frozenset[str], cap: int) -> GatedQuery:
    """Parse, validate, scope, and cap. Raises SqlDeniedError."""
    if not allowed:
        raise SqlDeniedError("you have no tables granted")
    stmt = parse_one(sql)
    tables = validate_and_scope(stmt, schema.lower(), frozenset(t.lower() for t in allowed))
    capped = apply_cap(stmt, cap)
    return GatedQuery(sql=capped.sql(dialect=DIALECT), tables=frozenset(tables), cap=cap)
