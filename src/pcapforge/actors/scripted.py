"""TCP services whose conversations the client side scripts (HTTPS, WSUS).

The client knows what the server answers: before it sends a request it hands the server the size
of that request and the bytes of the reply (``ScriptedConnection.exchange``). The server reads
exactly the request and writes the reply, so both sides are real sockets and the recording holds
the real segments. A server-side close (an idle timeout) is scripted the same way: the server
closes first, and the client closes when it sees the end of the stream.
"""

from __future__ import annotations

import asyncio
import socket

SOCKET_TIMEOUT = 5.0


class _Stopper:
    def __init__(self, server) -> None:
        self.server = server

    async def shutdown(self) -> None:
        self.server.close()


class ScriptedServer:
    """Listening side of one host and port; one step queue per client connection."""

    def __init__(self) -> None:
        self.steps: dict[tuple[str, int], asyncio.Queue] = {}

    async def start(self, rt, address: str, port: int) -> None:
        server = await asyncio.start_server(self._handle, address, port)
        rt.servers.append(_Stopper(server))

    def _queue(self, peer: tuple[str, int]) -> asyncio.Queue:
        return self.steps.setdefault(peer, asyncio.Queue())

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = tuple(writer.get_extra_info("peername")[:2])
        steps = self._queue(peer)
        try:
            while True:
                size, reply, close = await steps.get()
                if size:
                    try:
                        await reader.readexactly(size)
                    except (asyncio.IncompleteReadError, ConnectionError):
                        break
                if reply:
                    writer.write(reply)
                    await writer.drain()
                if close:
                    break
        finally:
            writer.close()
            self.steps.pop(peer, None)

    def push(self, rt, peer: tuple[str, int], size: int, reply: bytes, close: bool = False) -> None:
        rt.loop.call_soon_threadsafe(lambda: self._queue(peer).put_nowait((size, reply, close)))


class ScriptedConnection:
    """Client side: one TCP connection from ``source`` to a ``ScriptedServer``."""

    def __init__(self, rt, server: ScriptedServer, source: str, target: str, port: int) -> None:
        self.rt = rt
        self.server = server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.bind((source, 0))
            sock.connect((target, port))
        except BaseException:
            sock.close()
            raise
        self.sock = sock
        self.peer = sock.getsockname()[:2]

    def exchange(self, request: bytes, reply: bytes) -> None:
        """Send ``request`` and wait until the server's ``reply`` has arrived."""
        self.server.push(self.rt, self.peer, len(request), reply)
        if request:
            self.sock.sendall(request)
        received = 0
        while received < len(reply):
            chunk = self.sock.recv(min(65536, len(reply) - received))
            if not chunk:
                raise RuntimeError("connection closed by the server")
            received += len(chunk)

    def server_close(self, last: bytes = b"") -> None:
        """The server sends ``last`` and closes the connection; the client closes once it has seen that."""
        self.server.push(self.rt, self.peer, 0, last, close=True)
        while self.sock.recv(65536):
            pass
        self.sock.close()

    def close(self) -> None:
        self.sock.close()
