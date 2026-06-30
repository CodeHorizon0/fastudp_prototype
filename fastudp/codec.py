from __future__ import annotations

import struct
from typing import Optional, Tuple

from .constants import (
    FLAG_ENCRYPTED,
    HEADER_SIZE,
    HEADER_STRUCT,
    MAGIC,
    MAX_CLIENT_ID_BYTES,
    MAX_TICKET_BYTES,
    METHOD_NONE,
    VERSION,
)
from .exceptions import PacketTooLarge, ProtocolError, SecurityError


class PacketCodec:
    @staticmethod
    def pack_header(
        msg_type: int,
        flags: int,
        session_id: int,
        stream_id: int,
        seq: int,
        request_id: int,
        path_len: int,
        body_len: int,
        method: int = METHOD_NONE,
    ) -> bytes:
        combined_flags = ((method & 0xFF) << 8) | (flags & 0xFF)
        return HEADER_STRUCT.pack(
            MAGIC,
            VERSION,
            msg_type,
            combined_flags,
            session_id,
            stream_id,
            seq,
            request_id,
            path_len,
            body_len,
        )

    @staticmethod
    def unpack_header(data: bytes) -> Tuple[int, int, int, int, int, int, int, int, int]:
        if len(data) < HEADER_SIZE:
            raise PacketTooLarge("packet smaller than header")
        magic, version, msg_type, combined_flags, session_id, stream_id, seq, request_id, path_len, body_len = HEADER_STRUCT.unpack_from(data, 0)
        if magic != MAGIC or version != VERSION:
            raise ProtocolError("invalid packet header")
        method = (combined_flags >> 8) & 0xFF
        flags = combined_flags & 0xFF
        return msg_type, method, flags, session_id, stream_id, seq, request_id, path_len, body_len

    @staticmethod
    def nonce(stream_id: int, seq: int) -> bytes:
        return struct.pack("!IQ", stream_id & 0xFFFFFFFF, seq & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def encode_body_plain(status_code: int, content_type: str, body: bytes) -> bytes:
        ctype = content_type.encode("utf-8")
        if len(ctype) > 65535:
            raise PacketTooLarge("content type too large")
        return struct.pack("!H H", status_code & 0xFFFF, len(ctype)) + ctype + body

    @staticmethod
    def decode_body_plain(body: bytes) -> Tuple[int, str, bytes]:
        if len(body) < 4:
            raise ProtocolError("response body too small")
        status_code, ctype_len = struct.unpack_from("!HH", body, 0)
        offset = 4
        if len(body) < offset + ctype_len:
            raise ProtocolError("response content type truncated")
        content_type = body[offset:offset + ctype_len].decode("utf-8")
        payload = body[offset + ctype_len:]
        return status_code, content_type, payload

    @staticmethod
    def encode_hello(client_id: str, cnonce: bytes, ts: int, resume_ticket: bytes, mac_value: bytes) -> bytes:
        cid = client_id.encode("utf-8")
        if len(cid) > MAX_CLIENT_ID_BYTES:
            raise SecurityError("client id too large")
        if len(resume_ticket) > MAX_TICKET_BYTES:
            raise SecurityError("ticket too large")
        return (
            len(cid).to_bytes(2, "big")
            + cid
            + ts.to_bytes(8, "big")
            + cnonce
            + len(resume_ticket).to_bytes(2, "big")
            + resume_ticket
            + mac_value
        )

    @staticmethod
    def decode_hello(body: bytes) -> Tuple[str, bytes, int, bytes, bytes]:
        if len(body) < 2 + 8 + 16 + 2 + 32:
            raise SecurityError("hello packet too small")
        name_len = int.from_bytes(body[0:2], "big")
        offset = 2
        if name_len == 0 or name_len > MAX_CLIENT_ID_BYTES:
            raise SecurityError("invalid client id length")
        if len(body) < offset + name_len + 8 + 16 + 2 + 32:
            raise SecurityError("hello packet truncated")
        client_id = body[offset:offset + name_len].decode("utf-8")
        offset += name_len
        ts = int.from_bytes(body[offset:offset + 8], "big")
        offset += 8
        cnonce = body[offset:offset + 16]
        offset += 16
        ticket_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if len(body) < offset + ticket_len + 32:
            raise SecurityError("hello ticket truncated")
        ticket = body[offset:offset + ticket_len]
        offset += ticket_len
        mac_value = body[offset:offset + 32]
        return client_id, cnonce, ts, ticket, mac_value

    @staticmethod
    def encode_challenge(client_id: str, cnonce: bytes, snonce: bytes, cookie: bytes, ts: int, mac_value: bytes) -> bytes:
        cid = client_id.encode("utf-8")
        if len(cid) > MAX_CLIENT_ID_BYTES:
            raise SecurityError("client id too large")
        if len(cookie) > 65535:
            raise SecurityError("cookie too large")
        return len(cid).to_bytes(2, "big") + cid + ts.to_bytes(8, "big") + cnonce + snonce + len(cookie).to_bytes(2, "big") + cookie + mac_value

    @staticmethod
    def decode_challenge(body: bytes) -> Tuple[str, bytes, bytes, bytes, int, bytes]:
        if len(body) < 2 + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("challenge packet too small")
        name_len = int.from_bytes(body[0:2], "big")
        offset = 2
        if name_len == 0 or name_len > MAX_CLIENT_ID_BYTES:
            raise SecurityError("invalid client id length")
        if len(body) < offset + name_len + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("challenge packet truncated")
        client_id = body[offset:offset + name_len].decode("utf-8")
        offset += name_len
        ts = int.from_bytes(body[offset:offset + 8], "big")
        offset += 8
        cnonce = body[offset:offset + 16]
        offset += 16
        snonce = body[offset:offset + 16]
        offset += 16
        cookie_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if len(body) < offset + cookie_len + 32:
            raise SecurityError("challenge cookie truncated")
        cookie = body[offset:offset + cookie_len]
        offset += cookie_len
        mac_value = body[offset:offset + 32]
        return client_id, cnonce, snonce, cookie, ts, mac_value

    @staticmethod
    def encode_prove(client_id: str, cnonce: bytes, snonce: bytes, cookie: bytes, ts: int, mac_value: bytes) -> bytes:
        cid = client_id.encode("utf-8")
        if len(cid) > MAX_CLIENT_ID_BYTES:
            raise SecurityError("client id too large")
        if len(cookie) > 65535:
            raise SecurityError("cookie too large")
        return len(cid).to_bytes(2, "big") + cid + ts.to_bytes(8, "big") + cnonce + snonce + len(cookie).to_bytes(2, "big") + cookie + mac_value

    @staticmethod
    def decode_prove(body: bytes) -> Tuple[str, bytes, bytes, bytes, int, bytes]:
        if len(body) < 2 + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("prove packet too small")
        name_len = int.from_bytes(body[0:2], "big")
        offset = 2
        if name_len == 0 or name_len > MAX_CLIENT_ID_BYTES:
            raise SecurityError("invalid client id length")
        if len(body) < offset + name_len + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("prove packet truncated")
        client_id = body[offset:offset + name_len].decode("utf-8")
        offset += name_len
        ts = int.from_bytes(body[offset:offset + 8], "big")
        offset += 8
        cnonce = body[offset:offset + 16]
        offset += 16
        snonce = body[offset:offset + 16]
        offset += 16
        cookie_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if len(body) < offset + cookie_len + 32:
            raise SecurityError("prove cookie truncated")
        cookie = body[offset:offset + cookie_len]
        offset += cookie_len
        mac_value = body[offset:offset + 32]
        return client_id, cnonce, snonce, cookie, ts, mac_value

    @staticmethod
    def encode_ack(session_id: int, client_id: str, cnonce: bytes, snonce: bytes, ts: int, ticket: bytes, mac_value: bytes) -> bytes:
        cid = client_id.encode("utf-8")
        if len(cid) > MAX_CLIENT_ID_BYTES:
            raise SecurityError("client id too large")
        if len(ticket) > MAX_TICKET_BYTES:
            raise SecurityError("ticket too large")
        return (
            session_id.to_bytes(8, "big")
            + len(cid).to_bytes(2, "big")
            + cid
            + ts.to_bytes(8, "big")
            + cnonce
            + snonce
            + len(ticket).to_bytes(2, "big")
            + ticket
            + mac_value
        )

    @staticmethod
    def decode_ack(body: bytes) -> Tuple[int, str, bytes, bytes, int, bytes, bytes]:
        if len(body) < 8 + 2 + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("ack packet too small")
        session_id = int.from_bytes(body[0:8], "big")
        offset = 8
        name_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if name_len == 0 or name_len > MAX_CLIENT_ID_BYTES:
            raise SecurityError("invalid client id length")
        if len(body) < offset + name_len + 8 + 16 + 16 + 2 + 32:
            raise SecurityError("ack packet truncated")
        client_id = body[offset:offset + name_len].decode("utf-8")
        offset += name_len
        ts = int.from_bytes(body[offset:offset + 8], "big")
        offset += 8
        cnonce = body[offset:offset + 16]
        offset += 16
        snonce = body[offset:offset + 16]
        offset += 16
        ticket_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if len(body) < offset + ticket_len + 32:
            raise SecurityError("ack ticket truncated")
        ticket = body[offset:offset + ticket_len]
        offset += ticket_len
        mac_value = body[offset:offset + 32]
        return session_id, client_id, cnonce, snonce, ts, ticket, mac_value

    @staticmethod
    def encode_path_challenge(token: bytes) -> bytes:
        if len(token) != 16:
            raise SecurityError("path challenge token must be 16 bytes")
        return token

    @staticmethod
    def decode_path_challenge(body: bytes) -> bytes:
        if len(body) != 16:
            raise SecurityError("invalid path challenge token")
        return body

    @staticmethod
    def encode_path_response(token: bytes) -> bytes:
        return PacketCodec.encode_path_challenge(token)

    @staticmethod
    def decode_path_response(body: bytes) -> bytes:
        return PacketCodec.decode_path_challenge(body)

    @staticmethod
    def encode_ticket_payload(session_id: int, session_key: bytes, client_id: str, issued_at: int, expires_at: int) -> bytes:
        cid = client_id.encode("utf-8")
        if len(cid) > MAX_CLIENT_ID_BYTES:
            raise SecurityError("client id too large")
        if len(session_key) != 32:
            raise SecurityError("invalid session key length")
        return (
            session_id.to_bytes(8, "big")
            + issued_at.to_bytes(8, "big")
            + expires_at.to_bytes(8, "big")
            + len(cid).to_bytes(2, "big")
            + cid
            + session_key
        )

    @staticmethod
    def decode_ticket_payload(payload: bytes) -> Tuple[int, int, int, str, bytes]:
        if len(payload) < 8 + 8 + 8 + 2 + 32:
            raise SecurityError("ticket payload too small")
        session_id = int.from_bytes(payload[0:8], "big")
        issued_at = int.from_bytes(payload[8:16], "big")
        expires_at = int.from_bytes(payload[16:24], "big")
        name_len = int.from_bytes(payload[24:26], "big")
        offset = 26
        if name_len == 0 or name_len > MAX_CLIENT_ID_BYTES:
            raise SecurityError("invalid ticket client id length")
        if len(payload) < offset + name_len + 32:
            raise SecurityError("ticket payload truncated")
        client_id = payload[offset:offset + name_len].decode("utf-8")
        offset += name_len
        session_key = payload[offset:offset + 32]
        return session_id, issued_at, expires_at, client_id, session_key
