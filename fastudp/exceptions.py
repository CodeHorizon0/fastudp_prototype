from __future__ import annotations


class ProtocolError(Exception):
    pass


class HandshakeError(ProtocolError):
    pass


class RouteNotFound(ProtocolError):
    pass


class RequestTimeout(ProtocolError):
    pass


class PacketTooLarge(ProtocolError):
    pass


class SecurityError(ProtocolError):
    pass


class ConnectionClosed(ProtocolError):
    pass
