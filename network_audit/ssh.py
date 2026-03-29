"""SSH client helpers."""

import os
import paramiko


def create_ssh_client():
    """Create a paramiko SSHClient with auto-add host key policy.

    Note:
        Uses AutoAddPolicy which automatically accepts unknown host keys.
        This is convenient for network device scanning but does not verify
        host identity. Do not use in security-sensitive contexts where
        host key verification is required.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def ssh_connect(host, username, password, timeout, use_keys=False):
    """Connect to a host via SSH and return the connected client.

    Args:
        host: Hostname or IP address.
        username: SSH username.
        password: SSH password (None for key-based auth).
        timeout: Connection timeout in seconds.
        use_keys: If True and no password, use SSH key auth.

    Returns:
        Connected paramiko.SSHClient (caller must close).

    Raises:
        paramiko.AuthenticationException: If authentication fails.
        paramiko.SSHException: If SSH protocol fails.
    """
    client = create_ssh_client()
    hostname, port = host, 22
    if ":" in host:
        parts = host.rsplit(":", 1)
        try:
            hostname, port = parts[0], int(parts[1])
        except ValueError:
            pass
    connect_kwargs = dict(hostname=hostname, port=port, username=username, timeout=timeout)

    if password:
        connect_kwargs["password"] = password
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    else:
        # Key-based auth: try id_ed25519 explicitly, also search for other keys and agent
        if use_keys:
            key_file = os.path.expanduser("~/.ssh/id_ed25519")
            if os.path.exists(key_file):
                connect_kwargs["key_filename"] = key_file
            # Always allow agent auth and key search as fallbacks
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

    try:
        client.connect(**connect_kwargs)
    except (paramiko.AuthenticationException, paramiko.SSHException):
        client.close()
        raise
    return client
