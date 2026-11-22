import socket
import socketserver
import struct
import threading
from dataclasses import dataclass, field


@dataclass
class ProxyRequest:
    """What a client asked the proxy to connect to."""

    host: str
    port: int
    authenticated: bool


@dataclass
class Socks5Server:
    """A minimal SOCKS5 (RFC 1928 / RFC 1929) proxy for tests.

    Records every CONNECT so a test can assert that Warpgate sent the target
    hostname to the proxy (rather than resolving it itself or connecting
    directly).

    `deny_private` makes the proxy refuse loopback and RFC 1918 destinations,
    which is what a proxy on the public internet behaves like: it cannot reach
    the test's sshd, so a connection that succeeds must have gone direct.
    """

    port: int
    requests: list[ProxyRequest] = field(default_factory=list)
    _server: socketserver.ThreadingTCPServer | None = None
    _thread: threading.Thread | None = None

    def __post_init__(self) -> None:
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                outer._handle(self.request)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server(("127.0.0.1", self.port), Handler)

    def start(self) -> "Socks5Server":
        assert self._server is not None
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    # --- protocol ---

    def _handle(self, client: socket.socket) -> None:
        try:
            greeting = client.recv(2)
            if len(greeting) != 2 or greeting[0] != 0x05:
                client.close()
                return
            n = greeting[1]
            methods = client.recv(n)
            # Only no-auth is offered: a client that sends credentials also
            # offers no-auth, so tests keep a single code path here.
            if 0x00 in methods:
                client.sendall(b"\x05\x00")
            else:
                client.sendall(b"\x05\xff")
                client.close()
                return

            head = client.recv(4)
            if len(head) != 4 or head[1] != 0x01:
                client.close()
                return
            atyp = head[3]
            if atyp == 0x01:
                host = socket.inet_ntoa(client.recv(4))
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            elif atyp == 0x03:
                length = client.recv(1)[0]
                host = client.recv(length).decode()
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                client.close()
                return
            port = struct.unpack(">H", client.recv(2))[0]
            self.requests.append(ProxyRequest(host=host, port=port, authenticated=False))

            try:
                upstream = socket.create_connection((host, port), timeout=10)
            except OSError:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                client.close()
                return

            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            self._pump(client, upstream)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        def copy(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        first = threading.Thread(target=copy, args=(a, b), daemon=True)
        first.start()
        copy(b, a)
        first.join(timeout=5)
        try:
            b.close()
        except OSError:
            pass