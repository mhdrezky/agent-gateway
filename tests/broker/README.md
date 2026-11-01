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

`.keys/` holds a throwaway key and must not be committed.
