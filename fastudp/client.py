from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .codec import PacketCodec
from .constants import (
    DEFAULT_RETRIES,
    DEFAULT_STREAM_LIMIT,
    DEFAULT_TIMEOUT,
    FLAG_ENCRYPTED,
    FLAG_RESPONSE,
    HEADER_SIZE,
    MAX_BODY_BYTES,
    MAX_CLIENT_ID_BYTES,
    MAX_PACKET_SIZE,
    MAX_PATH_BYTES,
    MSG_ACK,
    MSG_CHALLENGE,
    MSG_CLOSE,
    MSG_FRAME_ACK,
    MSG_HELLO,
    MSG_PATH_CHALLENGE,
    MSG_PATH_RESPONSE,
    MSG_PONG,
    MSG_PROVE,
    MSG_REQUEST,
    MSG_RESPONSE,
)
from .exceptions import ConnectionClosed, HandshakeError, PacketTooLarge, ProtocolError, RequestTimeout, SecurityError
from .routing import Response
from .security import ReplayWindow, derive_session_key, mac, now_ts, open_ticket, seal_ticket, ts_ok


@dataclass(slots=True)
class StreamState:
    stream_id: int
    next_request_id: int = 1
    next_seq: int = 0
    pending: Dict[int, asyncio.Future[Response]] = field(default_factory=dict)
    acked: Dict[int, asyncio.Event] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass(slots=True)
class TransportSession:
    client: "FastUDPClient"
    session_id: int
    session_key: bytes
    server_addr: Tuple[str, int]
    client_id: str
    resumption_ticket: bytes = b""
    streams: Dict[int, StreamState] = field(default_factory=dict)
    closed: bool = False

    def channel(self, stream_id: int) -> "TransportChannel":
        return TransportChannel(self, stream_id)

    def get_stream(self, stream_id: int) -> StreamState:
        stream = self.streams.get(stream_id)
        if stream is None:
            if len(self.streams) >= self.client.max_streams:
                raise ProtocolError("stream limit reached")
            stream = StreamState(stream_id=stream_id)
            self.streams[stream_id] = stream
        return stream


class TransportChannel:
    def __init__(self, session: TransportSession, stream_id: int) -> None:
        self.session = session
        self.stream_id = stream_id

    async def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> Response:
        return await self.session.client.request(
            method,
            path,
            body=body,
            json_data=json_data,
            timeout=timeout,
            retries=retries,
            stream_id=self.stream_id,
        )

    async def get(self, path: str, *, timeout: Optional[float] = None, retries: Optional[int] = None) -> Response:
        return await self.request("GET", path, timeout=timeout, retries=retries)

    async def post(
        self,
        path: str,
        *,
        body: Optional[bytes] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> Response:
        return await self.request("POST", path, body=body, json_data=json_data, timeout=timeout, retries=retries)


class ClientDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, client: "FastUDPClient") -> None:
        self.client = client

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.client.transport = transport  # type: ignore[assignment]
        if self.client.connected is not None and not self.client.connected.done():
            self.client.connected.set_result(True)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.client._on_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        return

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.client.transport = None
        if self.client.closed is not None and not self.client.closed.done():
            self.client.closed.set_result(True)


class FastUDPClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        psk: str,
        client_id: str,
        local_host: str = "0.0.0.0",
        local_port: int = 0,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        max_streams: int = DEFAULT_STREAM_LIMIT,
    ) -> None:
        self.host = host
        self.port = port
        self.psk = psk.encode("utf-8")
        self.client_id = client_id
        self.local_host = local_host
        self.local_port = local_port
        self.timeout = timeout
        self.retries = retries
        self.max_streams = max_streams
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[ClientDatagramProtocol] = None
        self.connected: Optional[asyncio.Future[bool]] = None
        self.closed: Optional[asyncio.Future[bool]] = None
        self.session: Optional[TransportSession] = None
        self.pending_handshake: Dict[str, Any] = {}
        self.pending_requests: Dict[Tuple[int, int], asyncio.Future[Response]] = {}
        self.streams: Dict[int, StreamState] = {}
        self.recv_windows: Dict[int, ReplayWindow] = {}
        self.server_addr = (host, port)
        self.resumption_ticket: bytes = b""

    async def connect(self) -> TransportSession:
        self.loop = asyncio.get_running_loop()
        self.connected = self.loop.create_future()
        self.closed = self.loop.create_future()
        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: ClientDatagramProtocol(self),
            local_addr=(self.local_host, self.local_port),
        )
        self.transport = transport  # type: ignore[assignment]
        self.protocol = protocol  # type: ignore[assignment]
        await self._handshake()
        if self.session is None:
            raise HandshakeError("handshake failed")
        return self.session

    def channel(self, stream_id: int) -> TransportChannel:
        if self.session is None:
            raise ProtocolError("connect first")
        return self.session.channel(stream_id)

    async def close(self) -> None:
        if self.transport is not None:
            self._send_close()
            self.transport.close()
            self.transport = None
        if self.session is not None:
            self.session.closed = True
        if self.closed is not None and not self.closed.done():
            self.closed.set_result(True)

    def _send(self, data: bytes) -> None:
        if self.transport is None:
            raise ProtocolError("transport is closed")
        self.transport.sendto(data, self.server_addr)

    def _send_close(self) -> None:
        if self.session is None:
            return
        header = PacketCodec.pack_header(MSG_CLOSE, 0, self.session.session_id, 0, 0, 0, 0, 0)
        self._send(header)

    def _on_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        if addr != self.server_addr:
            self.server_addr = addr
        if len(data) < HEADER_SIZE:
            return
        try:
            msg_type, method, flags, session_id, stream_id, seq, request_id, path_len, body_len = PacketCodec.unpack_header(data)
            offset = HEADER_SIZE
            if len(data) < offset + path_len + body_len:
                return
            body = data[offset + path_len:offset + path_len + body_len]
            if msg_type == MSG_CHALLENGE:
                self._on_challenge(body)
                return
            if msg_type == MSG_ACK:
                self._on_ack(body)
                return
            if msg_type == MSG_RESPONSE:
                self._on_response(session_id, stream_id, seq, request_id, body)
                return
            if msg_type == MSG_FRAME_ACK:
                self._on_frame_ack(session_id, stream_id, seq, request_id)
                return
            if msg_type == MSG_PATH_CHALLENGE:
                self._on_path_challenge(session_id, body, addr)
                return
            if msg_type == MSG_PONG:
                return
        except Exception:
            return

    async def _handshake(self) -> None:
        cnonce = secrets.token_bytes(16)
        ts = now_ts()
        hello_body = self._encode_hello(self.client_id, cnonce, ts, self.resumption_ticket, mac(self.psk, "HELLO", self.client_id, cnonce, ts, self.resumption_ticket))
        hello_header = PacketCodec.pack_header(MSG_HELLO, 0, 0, 0, 0, 0, 0, len(hello_body))
        self.pending_handshake = {"client_id": self.client_id, "cnonce": cnonce, "ts": ts}
        self._send(hello_header + hello_body)
        try:
            await asyncio.wait_for(asyncio.shield(self._wait_session_ready()), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise HandshakeError("handshake timeout") from exc

    async def _wait_session_ready(self) -> None:
        while self.session is None:
            await asyncio.sleep(0.01)

    def _encode_hello(self, client_id: str, cnonce: bytes, ts: int, ticket: bytes, mac_value: bytes) -> bytes:
        return PacketCodec.encode_hello(client_id, cnonce, ts, ticket, mac_value)

    def _decode_challenge(self, body: bytes) -> Tuple[str, bytes, bytes, bytes, int, bytes]:
        return PacketCodec.decode_challenge(body)

    def _decode_ack(self, body: bytes) -> Tuple[int, str, bytes, bytes, int, bytes, bytes]:
        return PacketCodec.decode_ack(body)

    def _on_challenge(self, body: bytes) -> None:
        try:
            client_id, cnonce, snonce, cookie, ts, mac_value = self._decode_challenge(body)
            if client_id != self.client_id:
                return
            if cnonce != self.pending_handshake.get("cnonce"):
                return
            expected = mac(self.psk, "CHALLENGE", client_id, cnonce, snonce, cookie, ts)
            if not hmac.compare_digest(expected, mac_value):
                return
            prove_ts = now_ts()
            prove_mac = mac(self.psk, "PROVE", client_id, cnonce, snonce, cookie, prove_ts)
            prove_body = PacketCodec.encode_prove(client_id, cnonce, snonce, cookie, prove_ts, prove_mac)
            prove_header = PacketCodec.pack_header(MSG_PROVE, 0, 0, 0, 0, 0, 0, len(prove_body))
            self.pending_handshake["snonce"] = snonce
            self.pending_handshake["cookie"] = cookie
            self._send(prove_header + prove_body)
        except Exception:
            return

    def _on_ack(self, body: bytes) -> None:
        try:
            session_id, client_id, cnonce, snonce, ts, ticket, mac_value = self._decode_ack(body)
            if client_id != self.client_id:
                return
            if cnonce != self.pending_handshake.get("cnonce"):
                return
            if ticket:
                self.resumption_ticket = ticket
                restored = self._restore_ticket(ticket)
                if restored is not None:
                    restored_session_id, session_key = restored
                    self.session = TransportSession(self, restored_session_id, session_key, self.server_addr, client_id, resumption_ticket=ticket)
                    self.session.resumption_ticket = ticket
                    return
            session_key = derive_session_key(self.psk, client_id, cnonce, snonce)
            self.session = TransportSession(self, session_id, session_key, self.server_addr, client_id, resumption_ticket=ticket)
        except Exception:
            return

    def _restore_ticket(self, ticket: bytes) -> Optional[Tuple[int, bytes]]:
        try:
            payload = open_ticket(self.psk, ticket)
            session_id, issued_at, expires_at, client_id, session_key = PacketCodec.decode_ticket_payload(payload)
            if client_id != self.client_id:
                return None
            if expires_at < now_ts():
                return None
            return session_id, session_key
        except Exception:
            return None

    def _on_response(self, session_id: int, stream_id: int, seq: int, request_id: int, body: bytes) -> None:
        if self.session is None or self.session.session_id != session_id:
            return
        window = self.recv_windows.setdefault(stream_id, ReplayWindow())
        if not window.accept(seq):
            return
        fut = self.pending_requests.pop((stream_id, request_id), None)
        if fut is None or fut.done():
            return
        try:
            plain = ChaCha20Poly1305(self.session.session_key).decrypt(
                PacketCodec.nonce(stream_id, seq),
                body,
                PacketCodec.pack_header(MSG_RESPONSE, FLAG_ENCRYPTED | FLAG_RESPONSE, session_id, stream_id, seq, request_id, 0, len(body)),
            )
            status_code, content_type, payload = PacketCodec.decode_body_plain(plain)
            fut.set_result(Response(status_code=status_code, content_type=content_type, body=payload))
        except Exception as exc:
            fut.set_exception(SecurityError(str(exc)))

    def _on_frame_ack(self, session_id: int, stream_id: int, seq: int, request_id: int) -> None:
        stream = self.streams.get(stream_id)
        if stream is None:
            return
        event = stream.acked.get(request_id)
        if event is not None:
            event.set()

    def _on_path_challenge(self, session_id: int, body: bytes, addr: Tuple[str, int]) -> None:
        if self.session is None or self.session.session_id != session_id:
            return
        try:
            token = PacketCodec.decode_path_challenge(body)
        except Exception:
            return
        response_body = PacketCodec.encode_path_response(token)
        header = PacketCodec.pack_header(MSG_PATH_RESPONSE, 0, session_id, 0, 0, 0, 0, len(response_body))
        self._send(header + response_body)
        self.server_addr = addr

    async def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        stream_id: int = 0,
    ) -> Response:
        if self.session is None:
            raise ProtocolError("connect first")
        if body is not None and json_data is not None:
            raise ValueError("use body or json_data")
        if json_data is not None:
            body = json.dumps(json_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if body is None:
            body = b""
        if len(body) > MAX_BODY_BYTES:
            raise PacketTooLarge("request body too large")
        timeout = self.timeout if timeout is None else timeout
        retries = self.retries if retries is None else retries
        stream = self.session.get_stream(stream_id)
        async with stream.lock:
            request_id = stream.next_request_id
            stream.next_request_id += 1
            seq = stream.next_seq
            stream.next_seq += 1

        path_bytes = path.encode("utf-8")
        if len(path_bytes) > MAX_PATH_BYTES:
            raise PacketTooLarge("path too large")
        method_code = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "PATCH": 5}.get(method.upper(), 0)
        nonce = PacketCodec.nonce(stream_id, seq)
        header = PacketCodec.pack_header(MSG_REQUEST, FLAG_ENCRYPTED, self.session.session_id, stream_id, seq, request_id, len(path_bytes), len(body) + 16, method=method_code)
        enc_body = ChaCha20Poly1305(self.session.session_key).encrypt(nonce, body, header + path_bytes)
        packet = header + path_bytes + enc_body

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Response] = loop.create_future()
        self.pending_requests[(stream_id, request_id)] = fut
        ack_event = asyncio.Event()
        stream.acked[request_id] = ack_event

        for attempt in range(retries + 1):
            self._send(packet)
            try:
                return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
            except asyncio.TimeoutError:
                if attempt >= retries:
                    self.pending_requests.pop((stream_id, request_id), None)
                    stream.acked.pop(request_id, None)
                    raise RequestTimeout(f"request timed out: {method} {path}")

        raise RequestTimeout("request timed out")

    async def get(self, path: str, *, timeout: Optional[float] = None, retries: Optional[int] = None, stream_id: int = 0) -> Response:
        return await self.request("GET", path, timeout=timeout, retries=retries, stream_id=stream_id)

    async def post(
        self,
        path: str,
        *,
        body: Optional[bytes] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        stream_id: int = 0,
    ) -> Response:
        return await self.request("POST", path, body=body, json_data=json_data, timeout=timeout, retries=retries, stream_id=stream_id)
