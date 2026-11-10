# Broker tests against real targets

These tests are marked `@pytest.mark.broker` and are excluded by default
(`addopts = "-m 'not broker'"`). Each test skips itself when its environment
variables are missing.

## SSH (`openssh-server` container)

```bash
cd tests/broker
mkdir -p .keys && ssh-keygen -t ed25519 -N "" -f .keys/id_ed25519
docker compose up -d sshd
# Pin the host key: take the SHA256 fingerprint of the ed25519 key.
ssh-keyscan -t ed25519 -p 2222 127.0.0.1 2>/dev/null | ssh-keygen -lf - | awk '{print $2}'
```

```bash
export AGW_TEST_SSH_HOST=127.0.0.1
export AGW_TEST_SSH_PORT=2222
export AGW_TEST_SSH_USER=deploy
export AGW_TEST_SSH_KEY_FILE=tests/broker/.keys/id_ed25519
export AGW_TEST_SSH_FINGERPRINT=SHA256:...   # output of the command above
uv run pytest -m broker tests/broker/test_ssh_live.py
```

The container has no systemd, so `ssh.service.*` return a non-zero exit code;
the tests only check that the fixed command ran and that output is sanitised.

## Docker

```bash
cd tests/broker && docker compose up -d managed unmanaged
export AGW_TEST_DOCKER_ENDPOINT=unix:///var/run/docker.sock   # or tcp://127.0.0.1:2375
uv run pytest -m broker tests/broker/test_docker_live.py
```

## SQL (Postgres container)

The stack has its own compose project and host port 15432, so it does not
collide with other stacks. `sql/init.sql` creates the `sample` schema and the
`agw_reader` login the tests use, plus what the catalog tests (`agw sync`) need:
comments, a table the reader may not read, and a mixed-case table. It only runs on
a fresh volume, so after it changes recreate the stack with `down -v`. The catalog
tests also log in as the owner (`agw_owner`) to create and drop a probe table.

```bash
docker compose -p agw-broker-sql -f tests/broker/docker-compose.sql.yml up -d --wait
export AGW_TEST_SQL_HOST=127.0.0.1
export AGW_TEST_SQL_PORT=15432
uv run pytest -m broker tests/broker/test_sql_live.py
docker compose -p agw-broker-sql -f tests/broker/docker-compose.sql.yml down -v
```

## SMTP (Mailpit)

Its own compose project (`agw-broker-smtp`) and host ports, so it never collides
with the agentgate dev stack, which runs Mailpit on 1025/8025. `mailpit` is plain
SMTP (delivery is checked through its HTTP API); `mailpit-tls` offers STARTTLS
with a self-signed certificate the broker must refuse.

```bash
docker compose -f tests/broker/docker-compose.smtp.yml up -d
export AGW_TEST_SMTP_HOST=127.0.0.1
export AGW_TEST_SMTP_PORT=11025
export AGW_TEST_MAILPIT_API=http://127.0.0.1:18025
export AGW_TEST_SMTP_TLS_PORT=11026
uv run pytest -m broker tests/broker/test_smtp_live.py
docker compose -f tests/broker/docker-compose.smtp.yml down
```

`.keys/` holds a throwaway key and must not be committed.
