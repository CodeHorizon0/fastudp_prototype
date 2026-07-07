from __future__ import annotations

import asyncio
import contextlib
import hmac
import inspect
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .codec import PacketCodec
from .constants import (
    DEFAULT_BURST,
    DEFAULT_PATH_VALIDATION_TTL,
    DEFAULT_RATE,
    DEFAULT_RESPONSE_CACHE_TTL,
    DEFAULT_RESUMPTION_TTL,
    DEFAULT_STREAM_LIMIT,
    FLAG_ENCRYPTED,
    FLAG_RESPONSE,
    FLAG_0RTT,
    HEADER_SIZE,
    MAX_BODY_BYTES,
    MAX_CLIENT_ID_BYTES,
    MAX_PACKET_SIZE,
    MAX_PATH_BYTES,
    MAX_PENDING_TTL,
    MAX_SESSION_TTL,
    MAX_TICKET_BYTES,
    METHOD_NAMES,
    METHOD_NONE,
    MSG_ACK,
    MSG_CHALLENGE,
    MSG_CLOSE,
    MSG_ERROR,
    MSG_FRAME_ACK,
    MSG_HELLO,
    MSG_PATH_CHALLENGE,
    MSG_PATH_RESPONSE,
    MSG_PING,
    MSG_PONG,
    MSG_PROVE,
    MSG_REQUEST,
    MSG_RESPONSE,
)
from .exceptions import ConnectionClosed, HandshakeError, PacketTooLarge, ProtocolError, RouteNotFound, SecurityError
from .routing import FastUDPApp, Request, Response, TransportSessionProxy, build_handler_kwargs, normalize_response, split_path
from .congestion import UDPCongestionController
from .security import ReplayWindow, TokenBucket, derive_session_key, mac, now_ts, open_ticket, seal_ticket, ts_ok


@dataclass(slots=True)
class PendingHandshake:
    client_id: str
    client_addr: Tuple[str, int]
    cnonce: bytes
    snonce: bytes
    cookie: bytes
    ts: int
    created_at: float
    expires_at: float


@dataclass(slots=True)
class SessionState:
    session_id: int
    client_id: str
    client_addr: Tuple[str, int]
    session_key: bytes
    created_at: float
    expires_at: float
    resumption_ticket: bytes = b""
    send_seqs: Dict[int, int] = field(default_factory=dict)
    recv_windows: Dict[int, ReplayWindow] = field(default_factory=dict)
    response_cache: Dict[Tuple[int, int], Tuple[bytes, float]] = field(default_factory=dict)
    inflight_requests: Dict[Tuple[int, int], float] = field(default_factory=dict)
    path_validation: Dict[Tuple[str, int], Tuple[bytes, float]] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.monotonic)
    closed: bool = False


class FastUDPServer(asyncio.DatagramProtocol):
    def __init__(
        self,
        *,
        psk: str,
        bind: str = "0.0.0.0",
        port: int = 9999,
        rate_limit_per_ip: float = DEFAULT_RATE,
        burst_per_ip: float = DEFAULT_BURST,
        session_ttl: float = MAX_SESSION_TTL,
        pending_ttl: float = MAX_PENDING_TTL,
        max_clients: int = 65535,
        max_streams_per_session: int = DEFAULT_STREAM_LIMIT,
        response_cache_ttl: float = DEFAULT_RESPONSE_CACHE_TTL,
        resumption_ttl: float = DEFAULT_RESUMPTION_TTL,
        path_validation_ttl: float = DEFAULT_PATH_VALIDATION_TTL,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.psk = psk.encode("utf-8")
        self.bind = bind
        self.port = port
        self.rate_limit_per_ip = rate_limit_per_ip
        self.burst_per_ip = burst_per_ip
        self.session_ttl = session_ttl
        self.pending_ttl = pending_ttl
        self.max_clients = max_clients
        self.max_streams_per_session = max_streams_per_session
        self.response_cache_ttl = response_cache_ttl
        self.resumption_ttl = resumption_ttl
        self.path_validation_ttl = path_validation_ttl

        self.app = FastUDPApp()
        self.router = self.app.router
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.pending: Dict[Tuple[str, int, str, bytes], PendingHandshake] = {}
        self.sessions: Dict[int, SessionState] = {}
        self.rate_limits: Dict[str, TokenBucket] = {}
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        self._closed = False
        self.congestion = UDPCongestionController()
        self.logger = logger or logging.getLogger("fastudp.server")

    def route(self, path: str, methods: Sequence[str]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.route(path, methods)

    def get(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.get(path)

    def post(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.post(path)

    def put(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.put(path)

    def delete(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.delete(path)

    def patch(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.app.patch(path)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.loop = asyncio.get_running_loop()
        self._cleanup_task = self.loop.create_task(self._cleanup_loop())
        sockname = transport.get_extra_info("sockname")
        self.logger.info("server listening on %s", sockname)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            self.logger.error("connection lost: %r", exc)
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            self._cleanup_task = None
        self.transport = None

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if self.transport is None:
            return
        if not self._rate_allow(addr[0]):
            self.logger.warning("rate limited packet from %s:%s", addr[0], addr[1])
            return
        if len(data) > MAX_PACKET_SIZE or len(data) < HEADER_SIZE:
            return
        try:
            msg_type, method, flags, session_id, stream_id, seq, request_id, path_len, body_len = PacketCodec.unpack_header(data)
            offset = HEADER_SIZE
            if path_len > MAX_PATH_BYTES or body_len > MAX_BODY_BYTES:
                raise PacketTooLarge("packet payload limit exceeded")
            if len(data) < offset + path_len + body_len:
                raise ProtocolError("truncated packet")
            path_bytes = data[offset:offset + path_len]
            body = data[offset + path_len:offset + path_len + body_len]

            if msg_type == MSG_HELLO:
                self._handle_hello(body, addr)
                return
            if msg_type == MSG_PROVE:
                self._handle_prove(body, addr)
                return
            if msg_type == MSG_PING:
                self._handle_ping(session_id, stream_id, seq, request_id, addr)
                return
            if msg_type == MSG_PATH_RESPONSE:
                self._handle_path_response(session_id, body, addr)
                return

            session = self.sessions.get(session_id)
            if session is None:
                self.logger.debug("unknown session_id=%s from %s:%s", session_id, addr[0], addr[1])
                return
            if time.monotonic() > session.expires_at:
                self.sessions.pop(session_id, None)
                self.logger.info("expired session_id=%s", session_id)
                return

            if session.client_addr != addr:
                if not self._path_validated(session, addr):
                    self._issue_path_challenge(session, addr)
                    return
                session.client_addr = addr

            session.last_activity = time.monotonic()

            if msg_type == MSG_REQUEST:
                self._handle_request(session, method, flags, stream_id, seq, request_id, path_bytes, body, addr)
                return
            if msg_type == MSG_RESPONSE:
                self._handle_response(session, flags, stream_id, seq, request_id, body)
                return
            if msg_type == MSG_FRAME_ACK:
                self._handle_frame_ack(session, stream_id, seq, request_id)
                return
            if msg_type == MSG_PONG:
                return
            if msg_type == MSG_CLOSE:
                session.closed = True
                self.sessions.pop(session_id, None)
                return
        except Exception as exc:
            self.logger.debug("datagram handling failed from %s:%s: %r", addr[0], addr[1], exc)

    def error_received(self, exc: Exception) -> None:
        self.logger.warning("socket error: %r", exc)

    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: self, local_addr=(self.bind, self.port))
        try:
            while self.transport is not None:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            with contextlib.suppress(Exception):
                await self._cleanup_task
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def _rate_allow(self, ip: str) -> bool:
        bucket = self.rate_limits.get(ip)
        if bucket is None:
            bucket = TokenBucket(self.rate_limit_per_ip, self.burst_per_ip)
            self.rate_limits[ip] = bucket
        return bucket.allow()

    async def _cleanup_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                now = time.monotonic()
                for key, pending in list(self.pending.items()):
                    if pending.expires_at < now:
                        self.pending.pop(key, None)
                for session_id, session in list(self.sessions.items()):
                    if session.expires_at < now or session.closed:
                        self.sessions.pop(session_id, None)
                        continue
                    for cache_key, (_, expires_at) in list(session.response_cache.items()):
                        if expires_at < now:
                            session.response_cache.pop(cache_key, None)
                    for cache_key, expires_at in list(session.inflight_requests.items()):
                        if expires_at < now:
                            session.inflight_requests.pop(cache_key, None)
                    for addr_key, (_, expires_at) in list(session.path_validation.items()):
                        if expires_at < now:
                            session.path_validation.pop(addr_key, None)
        except asyncio.CancelledError:
            return

    def _cookie(self, addr: Tuple[str, int], client_id: str, cnonce: bytes, ts: int) -> bytes:
        return mac(self.psk, "COOKIE", addr[0], addr[1], client_id, cnonce, ts)

    def _session_ticket(self, session: SessionState) -> bytes:
        payload = PacketCodec.encode_ticket_payload(
            session.session_id,
            session.session_key,
            session.client_id,
            int(time.time()),
            int(time.time() + self.resumption_ttl),
        )
        return seal_ticket(self.psk, payload)

    def _restore_ticket(self, ticket: bytes, client_id: str) -> Optional[Tuple[int, bytes]]:
        try:
            payload = open_ticket(self.psk, ticket)
            session_id, issued_at, expires_at, ticket_client_id, session_key = PacketCodec.decode_ticket_payload(payload)
            if ticket_client_id != client_id:
                return None
            if expires_at < int(time.time()):
                return None
            return session_id, session_key
        except Exception:
            return None

    def _encode_hello(self, client_id: str, cnonce: bytes, ts: int, ticket: bytes, mac_value: bytes) -> bytes:
        return PacketCodec.encode_hello(client_id, cnonce, ts, ticket, mac_value)

    def _decode_hello(self, body: bytes) -> Tuple[str, bytes, int, bytes, bytes]:
        return PacketCodec.decode_hello(body)

    def _encode_challenge(self, client_id: str, cnonce: bytes, snonce: bytes, cookie: bytes, ts: int, mac_value: bytes) -> bytes:
        return PacketCodec.encode_challenge(client_id, cnonce, snonce, cookie, ts, mac_value)

    def _decode_challenge(self, body: bytes) -> Tuple[str, bytes, bytes, bytes, int, bytes]:
        return PacketCodec.decode_challenge(body)

    def _encode_prove(self, client_id: str, cnonce: bytes, snonce: bytes, cookie: bytes, ts: int, mac_value: bytes) -> bytes:
        return PacketCodec.encode_prove(client_id, cnonce, snonce, cookie, ts, mac_value)

    def _decode_prove(self, body: bytes) -> Tuple[str, bytes, bytes, bytes, int, bytes]:
        return PacketCodec.decode_prove(body)

    def _encode_ack(self, session_id: int, client_id: str, cnonce: bytes, snonce: bytes, ts: int, ticket: bytes, mac_value: bytes) -> bytes:
        return PacketCodec.encode_ack(session_id, client_id, cnonce, snonce, ts, ticket, mac_value)

    def _decode_ack(self, body: bytes) -> Tuple[int, str, bytes, bytes, int, bytes, bytes]:
        return PacketCodec.decode_ack(body)

    def _verify_hello(self, body: bytes) -> Tuple[str, bytes, int, bytes]:
        client_id, cnonce, ts, ticket, mac_value = self._decode_hello(body)
        if not ts_ok(ts):
            raise HandshakeError("hello timestamp out of skew")
        expected = mac(self.psk, "HELLO", client_id, cnonce, ts, ticket)
        if not hmac.compare_digest(expected, mac_value):
            raise SecurityError("invalid hello mac")
        return client_id, cnonce, ts, ticket

    def _verify_prove(self, body: bytes, pending: PendingHandshake) -> None:
        client_id, cnonce, snonce, cookie, ts, mac_value = self._decode_prove(body)
        if client_id != pending.client_id:
            raise SecurityError("prove client_id mismatch")
        if cnonce != pending.cnonce or snonce != pending.snonce or cookie != pending.cookie:
            raise SecurityError("prove values mismatch")
        if not ts_ok(ts):
            raise HandshakeError("prove timestamp out of skew")
        expected = mac(self.psk, "PROVE", client_id, cnonce, snonce, cookie, ts)
        if not hmac.compare_digest(expected, mac_value):
            raise SecurityError("invalid prove mac")

    def _next_session_id(self) -> int:
        return secrets.randbits(63) | (1 << 63)

    def _handle_hello(self, body: bytes, addr: Tuple[str, int]) -> None:
        if len(self.sessions) >= self.max_clients:
            self.logger.warning("session limit reached, dropping hello from %s:%s", addr[0], addr[1])
            return
        client_id, cnonce, ts, ticket = self._verify_hello(body)
        if ticket:
            restored = self._restore_ticket(ticket, client_id)
            if restored is not None:
                session_id, session_key = restored
                session = self.sessions.get(session_id)
                if session is None:
                    session = SessionState(
                        session_id=session_id,
                        client_id=client_id,
                        client_addr=addr,
                        session_key=session_key,
                        created_at=time.monotonic(),
                        expires_at=time.monotonic() + self.session_ttl,
                        resumption_ticket=b"",
                    )
                    self.sessions[session_id] = session
                else:
                    session.client_addr = addr
                    session.session_key = session_key
                    session.expires_at = time.monotonic() + self.session_ttl
                    session.closed = False
                session.resumption_ticket = self._session_ticket(session)
                response_ts = now_ts()
                snonce = secrets.token_bytes(16)
                response_body = self._encode_ack(
                    session.session_id,
                    client_id,
                    cnonce,
                    snonce,
                    response_ts,
                    session.resumption_ticket,
                    mac(self.psk, "ACK", session.session_id, client_id, cnonce, snonce, response_ts, session.resumption_ticket),
                )
                header = PacketCodec.pack_header(MSG_ACK, 0, 0, 0, 0, 0, 0, len(response_body))
                self._send_packet(addr, header + response_body)
                self.logger.info("resumed session_id=%s client_id=%s addr=%s:%s", session.session_id, client_id, addr[0], addr[1])
                return

        snonce = secrets.token_bytes(16)
        cookie = self._cookie(addr, client_id, cnonce, ts)
        pending = PendingHandshake(
            client_id=client_id,
            client_addr=addr,
            cnonce=cnonce,
            snonce=snonce,
            cookie=cookie,
            ts=ts,
            created_at=time.monotonic(),
            expires_at=time.monotonic() + self.pending_ttl,
        )
        self.pending[(addr[0], addr[1], client_id, cnonce)] = pending
        response_ts = now_ts()
        response_body = self._encode_challenge(
            client_id,
            cnonce,
            snonce,
            cookie,
            response_ts,
            mac(self.psk, "CHALLENGE", client_id, cnonce, snonce, cookie, response_ts),
        )
        header = PacketCodec.pack_header(MSG_CHALLENGE, 0, 0, 0, 0, 0, 0, len(response_body))
        self._send_packet(addr, header + response_body)
        self.logger.info("handshake challenge sent to %s at %s:%s", client_id, addr[0], addr[1])

    def _handle_prove(self, body: bytes, addr: Tuple[str, int]) -> None:
        client_id, cnonce, _, _ = self._decode_prove(body)[:4]
        key = (addr[0], addr[1], client_id, cnonce)
        pending = self.pending.get(key)
        if pending is None:
            return
        if pending.expires_at < time.monotonic():
            self.pending.pop(key, None)
            self.logger.warning("expired pending handshake for %s at %s:%s", client_id, addr[0], addr[1])
            return
        self._verify_prove(body, pending)
        session_id = self._next_session_id()
        session_key = derive_session_key(self.psk, client_id, pending.cnonce, pending.snonce)
        session = SessionState(
            session_id=session_id,
            client_id=client_id,
            client_addr=addr,
            session_key=session_key,
            created_at=time.monotonic(),
            expires_at=time.monotonic() + self.session_ttl,
        )
        session.resumption_ticket = self._session_ticket(session)
        self.sessions[session_id] = session
        self.pending.pop(key, None)
        response_ts = now_ts()
        response_body = self._encode_ack(
            session_id,
            client_id,
            pending.cnonce,
            pending.snonce,
            response_ts,
            session.resumption_ticket,
            mac(self.psk, "ACK", session_id, client_id, pending.cnonce, pending.snonce, response_ts, session.resumption_ticket),
        )
        header = PacketCodec.pack_header(MSG_ACK, 0, 0, 0, 0, 0, 0, len(response_body))
        self._send_packet(addr, header + response_body)
        self.logger.info("session established session_id=%s client_id=%s addr=%s:%s", session_id, client_id, addr[0], addr[1])

    def _handle_ping(self, session_id: int, stream_id: int, seq: int, request_id: int, addr: Tuple[str, int]) -> None:
        session = self.sessions.get(session_id)
        if session is None:
            return
        if session.client_addr != addr:
            self._issue_path_challenge(session, addr)
            return
        session.last_activity = time.monotonic()
        window = session.recv_windows.setdefault(stream_id, ReplayWindow())
        if not window.accept(seq):
            return
        ts = now_ts()
        body = ts.to_bytes(8, "big")
        nonce = PacketCodec.nonce(stream_id, seq)
        aad = PacketCodec.pack_header(MSG_PONG, 0, session_id, stream_id, seq, request_id, 0, 8)
        cipher = ChaCha20Poly1305(session.session_key)
        enc_body = cipher.encrypt(nonce, body, aad)
        header = PacketCodec.pack_header(MSG_PONG, FLAG_ENCRYPTED, session_id, stream_id, seq, request_id, 0, len(enc_body))
        self._send_packet(addr, header + enc_body)

    def _handle_path_response(self, session_id: int, body: bytes, addr: Tuple[str, int]) -> None:
        session = self.sessions.get(session_id)
        if session is None:
            return
        token = PacketCodec.decode_path_response(body)
        addr_key = (addr[0], addr[1])
        pending = session.path_validation.get(addr_key)
        if pending is None:
            return
        expected_token, expires_at = pending
        if expires_at < time.monotonic() or not hmac.compare_digest(expected_token, token):
            return
        session.client_addr = addr
        session.path_validation.pop(addr_key, None)
        self.logger.info("path validated session_id=%s addr=%s:%s", session_id, addr[0], addr[1])

    def _path_validated(self, session: SessionState, addr: Tuple[str, int]) -> bool:
        pending = session.path_validation.get((addr[0], addr[1]))
        if pending is None:
            return False
        token, expires_at = pending
        return expires_at >= time.monotonic() and bool(token)

    def _issue_path_challenge(self, session: SessionState, addr: Tuple[str, int]) -> None:
        addr_key = (addr[0], addr[1])
        token, expires_at = session.path_validation.get(addr_key, (b"", 0.0))
        if expires_at < time.monotonic() or not token:
            token = secrets.token_bytes(16)
            expires_at = time.monotonic() + self.path_validation_ttl
            session.path_validation[addr_key] = (token, expires_at)
            body = PacketCodec.encode_path_challenge(token)
            header = PacketCodec.pack_header(MSG_PATH_CHALLENGE, 0, session.session_id, 0, 0, 0, 0, len(body))
            self._send_packet(addr, header + body)
            self.logger.debug("path challenge sent session_id=%s addr=%s:%s", session.session_id, addr[0], addr[1])

    def _handle_request(
        self,
        session: SessionState,
        method: int,
        flags: int,
        stream_id: int,
        seq: int,
        request_id: int,
        path_bytes: bytes,
        body: bytes,
        addr: Tuple[str, int],
    ) -> None:
        cache_key = (stream_id, request_id)
        cached = session.response_cache.get(cache_key)
        if cached is not None:
            packet, _ = cached
            self._send_packet(addr, packet)
            return

        window = session.recv_windows.setdefault(stream_id, ReplayWindow())
        if not window.accept(seq):
            self.logger.debug("replay rejected session_id=%s stream=%s seq=%s", session.session_id, stream_id, seq)
            return

        if not path_bytes:
            return
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return

        try:
            decrypted = ChaCha20Poly1305(session.session_key).decrypt(
                PacketCodec.nonce(stream_id, seq),
                body,
                PacketCodec.pack_header(
                    MSG_REQUEST,
                    flags,
                    session.session_id,
                    stream_id,
                    seq,
                    request_id,
                    len(path_bytes),
                    len(body),
                    method=method,
                )
                + path_bytes,
            )
        except Exception as exc:
            self.logger.debug("request decrypt failed session_id=%s stream=%s seq=%s: %r", session.session_id, stream_id, seq, exc)
            return

        ack_packet = PacketCodec.pack_header(MSG_FRAME_ACK, 0, session.session_id, stream_id, seq, request_id, 0, 0)
        self._send_packet(addr, ack_packet)

        route_path, query_params = split_path(path)
        try:
            handler, path_params = self.router.match(METHOD_NAMES.get(method, "NONE"), route_path)
        except RouteNotFound:
            response = Response.json({"detail": "not found"}, status_code=404)
            self._send_response(session, stream_id, seq, request_id, response, addr)
            return

        request = Request(
            app=self.app,
            transport=TransportSessionProxy(session, self),
            method=METHOD_NAMES.get(method, "NONE"),
            path=route_path,
            raw_path=path,
            query_params=query_params,
            path_params=path_params,
            body=decrypted,
            stream_id=stream_id,
            request_id=request_id,
        )
        task = asyncio.create_task(self._invoke_handler(handler, request))
        session.inflight_requests[cache_key] = time.monotonic() + 10.0
        task.add_done_callback(lambda fut: self._finish_request(fut, session, stream_id, seq, request_id, addr))
        self.logger.debug("request accepted session_id=%s stream=%s seq=%s %s %s", session.session_id, stream_id, seq, request.method, request.path)

    def _finish_request(
        self,
        fut: asyncio.Future[Response],
        session: SessionState,
        stream_id: int,
        seq: int,
        request_id: int,
        addr: Tuple[str, int],
    ) -> None:
        try:
            response = fut.result()
        except Exception as exc:
            self.logger.exception("handler failed session_id=%s stream=%s request_id=%s", session.session_id, stream_id, request_id)
            response = Response.json({"detail": "internal server error", "error": str(exc)}, status_code=500)
        self._send_response(session, stream_id, seq, request_id, response, addr)

    def _send_response(
        self,
        session: SessionState,
        stream_id: int,
        seq: int,
        request_id: int,
        response: Response,
        addr: Tuple[str, int],
    ) -> None:
        body_plain = PacketCodec.encode_body_plain(response.status_code, response.content_type, response.body)
        nonce = PacketCodec.nonce(stream_id, seq)
        header = PacketCodec.pack_header(
            MSG_RESPONSE,
            FLAG_ENCRYPTED | FLAG_RESPONSE,
            session.session_id,
            stream_id,
            seq,
            request_id,
            0,
            len(body_plain) + 16,
        )
        encrypted = ChaCha20Poly1305(session.session_key).encrypt(nonce, body_plain, header)
        packet = header + encrypted
        session.response_cache[(stream_id, request_id)] = (packet, time.monotonic() + self.response_cache_ttl)
        session.inflight_requests.pop((stream_id, request_id), None)
        self._send_packet(addr, packet)

    def _handle_response(self, session: SessionState, flags: int, stream_id: int, seq: int, request_id: int, body: bytes) -> None:
        return

    def _handle_frame_ack(self, session: SessionState, stream_id: int, seq: int, request_id: int) -> None:
        return

    def _send_packet(self, addr: Tuple[str, int], packet: bytes) -> None:
        if self.transport is not None:
            self.transport.sendto(packet, addr)

    async def _invoke_handler(self, handler: Callable[..., Any], request: Request) -> Response:
        kwargs = build_handler_kwargs(handler, request)
        result = handler(**kwargs)
        if inspect.isawaitable(result):
            result = await result  # type: ignore[assignment]
        return normalize_response(result)
