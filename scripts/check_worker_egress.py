"""Run inside the Compose worker to test its actual network boundary, without mocks."""

from __future__ import annotations

import socket
import ssl

# Both stacks must lack a direct external path, independent of the Git URL validator.
for host in ("1.1.1.1", "2606:4700:4700::1111"):
    try:
        connection = socket.create_connection((host, 443), timeout=2)
    except OSError:
        continue
    connection.close()
    raise SystemExit("Worker could bypass the acquisition proxy using a direct socket.")

try:
    socket.getaddrinfo("example.com", 443)
except socket.gaierror:
    pass
else:
    raise SystemExit("Worker could send external DNS requests.")


def connect(target: str) -> tuple[socket.socket, int]:
    connection = socket.create_connection(("github-egress", 8080), timeout=15)
    connection.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
    header = bytearray()
    while not header.endswith(b"\r\n\r\n") and len(header) < 16384:
        chunk = connection.recv(1)
        if not chunk:
            connection.close()
            raise RuntimeError("Proxy disconnected before responding.")
        header.extend(chunk)
    return connection, int(header.split(b" ", 2)[1])


for target in (
    "example.com:443",
    "github.com.example.com:443",
    "gist.github.com:443",
    "127.0.0.1:443",
    "169.254.169.254:443",
    "[::1]:443",
    "github.com:80",
):
    connection, status = connect(target)
    connection.close()
    if status != 403:
        raise SystemExit(f"Proxy failed to deny {target}: HTTP {status}")

# Prove that the allowlist works with end-to-end server certificate verification.
connection, status = connect("github.com:443")
if status != 200:
    connection.close()
    raise SystemExit(f"GitHub CONNECT failed: HTTP {status}")
with ssl.create_default_context().wrap_socket(connection, server_hostname="github.com") as tls:
    tls.sendall(b"HEAD / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n")
    if not tls.recv(64).startswith(b"HTTP/1.1 200"):
        raise SystemExit("GitHub TLS tunnel did not return a successful response.")
print("Worker egress checks passed: external sockets/DNS denied, GitHub TLS allowed.")
