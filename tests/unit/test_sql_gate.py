"""SQL gate tests, ported from the agentgate doorman's gate tests. The doorman's
``clamp_cap`` tests are gone: ``sql.query`` takes no row count from the agent, so
the cap is the resource's ``row_cap``."""

import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.sql import gate as sql_gate
from agent_gateway.brokers.sql.gate import SqlDeniedError

SCHEMA = "sample"
ALLOWED = frozenset({"purchase_order", "purchase_order_line", "product"})


def _scope(sql: str, allowed: frozenset[str]) -> tuple[str, str]:
    stmt = sql_gate.parse_one(sql)
    try:
        return "OK", ",".join(sorted(sql_gate.validate_and_scope(stmt, SCHEMA, allowed)))
    except SqlDeniedError as e:
        return "DENIED", str(e)


# --- scope denials ----------------------------------------------------------------


def test_single_forbidden_table_is_named() -> None:
    status, msg = _scope("SELECT * FROM customer", ALLOWED)
    assert status == "DENIED"
    assert "'customer'" in msg
    assert "purchase_order" in msg
    assert "not in your allowed set" in msg


def test_every_forbidden_table_reported_at_once() -> None:
    status, msg = _scope(
        "SELECT * FROM customer c JOIN sales_order s ON c.id = s.customer_id", ALLOWED
    )
    assert status == "DENIED"
    assert "'customer'" in msg
    assert "'sales_order'" in msg
    assert "tables" in msg


def test_only_the_forbidden_table_is_flagged_in_a_mix() -> None:
    status, msg = _scope(
        "SELECT * FROM purchase_order p JOIN customer c ON p.supplier_id = c.id", ALLOWED
    )
    assert status == "DENIED"
    assert "'customer'" in msg
    assert "'purchase_order'" not in msg


def test_duplicate_forbidden_reference_is_deduped() -> None:
    status, msg = _scope("SELECT * FROM customer a JOIN customer b ON a.id = b.id", ALLOWED)
    assert status == "DENIED"
    assert msg.count("'customer'") == 1


def test_fully_allowed_query_passes_and_pins_schema() -> None:
    stmt = sql_gate.parse_one(
        "SELECT doc_no FROM purchase_order JOIN purchase_order_line"
        " ON purchase_order.id = purchase_order_line.purchase_order_id"
    )
    referenced = sql_gate.validate_and_scope(stmt, SCHEMA, ALLOWED)
    assert referenced == {"purchase_order", "purchase_order_line"}
    assert "sample.purchase_order" in stmt.sql(dialect="postgres")


def test_empty_scope_message_is_graceful() -> None:
    status, msg = _scope("SELECT * FROM customer", frozenset())
    assert status == "DENIED"
    assert "no tables granted" in msg


def test_large_allowed_set_is_truncated() -> None:
    allowed = frozenset(f"t{i:03d}" for i in range(80))
    status, msg = _scope("SELECT * FROM zzz", allowed)
    assert status == "DENIED"
    assert "(+20 more)" in msg


@pytest.mark.parametrize(
    "sql", ["SELECT * FROM information_schema.tables", "SELECT * FROM other.purchase_order"]
)
def test_security_denials_do_not_leak_the_allowed_list(sql: str) -> None:
    status, msg = _scope(sql, ALLOWED)
    assert status == "DENIED"
    assert "Tables you can query" not in msg


def test_cross_database_reference_is_denied() -> None:
    status, msg = _scope("SELECT * FROM otherdb.sample.product", ALLOWED)
    assert status == "DENIED"
    assert msg == "cross-database references are not allowed"


def test_explicit_own_schema_is_accepted() -> None:
    assert _scope("SELECT * FROM sample.product", ALLOWED) == ("OK", "product")


def test_table_names_are_case_insensitive() -> None:
    assert _scope("SELECT * FROM Product", ALLOWED) == ("OK", "product")


# --- row cap ----------------------------------------------------------------------


def _limit(sql: str, cap: int) -> int:
    gated = sql_gate.gate(sql, SCHEMA, ALLOWED, cap)
    return int(gated.sql.rsplit("LIMIT", 1)[1])


def test_cap_applied() -> None:
    assert _limit("SELECT doc_no FROM purchase_order", 200) == 201  # cap + 1 detects "more"


def test_other_cap() -> None:
    assert _limit("SELECT doc_no FROM purchase_order", 500) == 501


def test_smaller_explicit_limit_is_honoured() -> None:
    gated = sql_gate.gate("SELECT doc_no FROM purchase_order LIMIT 10", SCHEMA, ALLOWED, 500)
    assert "LIMIT 10" in gated.sql  # the inner limit stays; the outer cap only bounds it


def test_explicit_limit_above_cap_is_bounded() -> None:
    gated = sql_gate.gate("SELECT doc_no FROM purchase_order LIMIT 9999", SCHEMA, ALLOWED, 500)
    assert gated.sql.rstrip().endswith("LIMIT 501")


def test_gated_query_carries_tables_and_cap() -> None:
    gated = sql_gate.gate("SELECT * FROM product", SCHEMA, ALLOWED, 7)
    assert gated.tables == {"product"}
    assert gated.cap == 7
    assert gated.sql == "SELECT * FROM (SELECT * FROM sample.product) AS q LIMIT 8"


# --- PostgreSQL ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM purchase_order",
        "UPDATE purchase_order SET status = 'closed'",
        "INSERT INTO purchase_order (doc_no) VALUES ('x')",
        "DROP TABLE purchase_order",
        "TRUNCATE purchase_order",
        "SELECT * INTO copy_of_po FROM purchase_order",
        "COPY purchase_order TO STDOUT",
        "WITH d AS (DELETE FROM purchase_order RETURNING *) SELECT * FROM d",
        "SET search_path TO public",
        "BEGIN",
        "SELECT * FROM purchase_order FOR UPDATE",
    ],
)
def test_writes_are_denied(sql: str) -> None:
    with pytest.raises(SqlDeniedError):
        sql_gate.gate(sql, SCHEMA, ALLOWED, 10)


@pytest.mark.parametrize(
    "fn",
    [
        "pg_read_file('/etc/passwd')",
        "pg_sleep(10)",
        "set_config('x', 'y', false)",
        "dblink('host=x', 'select 1')",
        "lo_import('/etc/passwd')",
    ],
)
def test_dangerous_functions_are_denied(fn: str) -> None:
    with pytest.raises(SqlDeniedError, match="not allowed"):
        sql_gate.gate(f"SELECT {fn} FROM purchase_order", SCHEMA, ALLOWED, 10)  # noqa: S608


def test_more_than_one_statement_is_denied() -> None:
    with pytest.raises(SqlDeniedError, match="single statement"):
        sql_gate.gate("SELECT 1 FROM product; SELECT 2 FROM product", SCHEMA, ALLOWED, 10)


def test_system_catalogs_are_denied() -> None:
    with pytest.raises(SqlDeniedError):
        sql_gate.gate("SELECT * FROM pg_catalog.pg_tables", SCHEMA, ALLOWED, 10)
    with pytest.raises(SqlDeniedError):
        sql_gate.gate("SELECT * FROM pg_tables", SCHEMA, ALLOWED, 10)


def test_cte_names_are_not_tables() -> None:
    gated = sql_gate.gate(
        "WITH open_po AS (SELECT * FROM purchase_order WHERE status = 'open')"
        " SELECT count(*) FROM open_po",
        SCHEMA,
        ALLOWED,
        10,
    )
    assert gated.tables == {"purchase_order"}


def test_union_of_allowed_tables_passes() -> None:
    gated = sql_gate.gate(
        "SELECT id FROM product UNION SELECT id FROM purchase_order", SCHEMA, ALLOWED, 10
    )
    assert gated.tables == {"product", "purchase_order"}


def test_subquery_tables_are_checked() -> None:
    with pytest.raises(SqlDeniedError, match="'customer'"):
        sql_gate.gate(
            "SELECT * FROM product WHERE id IN (SELECT product_id FROM customer)",
            SCHEMA,
            ALLOWED,
            10,
        )


def test_query_with_no_tables_is_denied() -> None:
    with pytest.raises(SqlDeniedError, match="no allowed tables"):
        sql_gate.gate("SELECT 1", SCHEMA, ALLOWED, 10)


@pytest.mark.parametrize(("sql", "message"), [("", "empty query"), ("   ;  ", "empty query")])
def test_empty_query_is_denied(sql: str, message: str) -> None:
    with pytest.raises(SqlDeniedError, match=message):
        sql_gate.gate(sql, SCHEMA, ALLOWED, 10)


def test_unparsable_sql_is_denied() -> None:
    with pytest.raises(SqlDeniedError, match=r"could not parse SQL \("):
        sql_gate.gate("SELECT FROM WHERE (((", SCHEMA, ALLOWED, 10)


def test_no_allowed_tables_is_denied_before_parsing() -> None:
    with pytest.raises(SqlDeniedError, match="no tables granted"):
        sql_gate.gate("SELECT * FROM product", SCHEMA, frozenset(), 10)


def test_denial_is_a_broker_error() -> None:
    assert issubclass(SqlDeniedError, BrokerError)
