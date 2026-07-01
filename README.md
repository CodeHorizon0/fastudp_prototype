# fastudp

UDP transport layer with FastAPI-like route decorators and QUIC-inspired transport features.

## Included transport features:
- asyncio datagram transport
- binary packets
- PSK handshake
- AEAD payload protection
- replay protection
- stream multiplexing
- connection migration by authenticated address rebinding
- path validation frames
- session resumption tickets
- packet acknowledgments
- FastAPI-like route decorators

## Planned features:
- Automatic post quantum encryption
- Full path validation
- UDP congestion control
- UDP based hole punching

 - JWT BASED CRYPTO HANDSHAKE

## Run

```bash
python -m fastudp.cli server --bind 0.0.0.0 --port 9999 --psk secret123
python -m fastudp.cli client --host 127.0.0.1 --port 9999 --psk secret123 --client-id alice
```
