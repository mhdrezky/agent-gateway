"""Shell snippets the admin runs on the host during onboarding.

The gateway never gets root on the host: the admin creates a dedicated user and installs
the gateway's public key themselves, using commands shown here.
"""

import shlex

# Optional groups and what membership allows. Order is the order they are offered in.
OPTIONAL_GROUPS: dict[str, str] = {
    "systemd-journal": "read service logs (needed for ssh.logs.tail)",
    "docker": "run docker commands; root-equivalent on the host, only if you need it",
}


def install_key_for_current_user(public_key: str) -> list[str]:
    """For an existing user: run as that user."""
    quoted = shlex.quote(public_key)
    return [
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
        f"echo {quoted} >> ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
    ]


def create_user_with_key(user: str, public_key: str, groups: list[str]) -> list[str]:
    """For a new user: run as an admin with sudo (e.g. ubuntu). No password login is enabled."""
    u = shlex.quote(user)
    home = f"/home/{user}"
    ssh_dir = shlex.quote(f"{home}/.ssh")
    keys = shlex.quote(f"{home}/.ssh/authorized_keys")
    commands = [
        f'sudo adduser --disabled-password --gecos "" {u}',
        f"sudo install -d -m 700 -o {u} -g {u} {ssh_dir}",
        f"echo {shlex.quote(public_key)} | sudo tee -a {keys} > /dev/null",
        f"sudo chown {u}:{u} {keys} && sudo chmod 600 {keys}",
    ]
    commands += [f"sudo usermod -aG {shlex.quote(group)} {u}" for group in groups]
    return commands


def sudoers_path(user: str) -> str:
    return f"/etc/sudoers.d/{user}"


def grant_sudo(user: str) -> list[str]:
    """Passwordless sudo for ``user``, in its own file so it can be revoked on its own."""
    path = shlex.quote(sudoers_path(user))
    rule = shlex.quote(f"{user} ALL=(ALL) NOPASSWD:ALL")
    return [
        f"echo {rule} | sudo tee {path} > /dev/null",
        f"sudo chmod 440 {path} && sudo visudo -cf {path}",
    ]


def revoke_sudo(user: str) -> list[str]:
    return [f"sudo rm -f {shlex.quote(sudoers_path(user))}"]
