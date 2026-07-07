# fastudp

UDP transport layer with FastAPI-like route decorators and QUIC-inspired transport features.

## Included transport features:
- Asyncio datagram transport
- Binary packets
- PSK handshake
- AEAD payload protection
- Replay protection
- Stream multiplexing
- Connection migration by authenticated address rebinding
- Path validation frames
- Session resumption tickets
- Packet acknowledgments
- FastAPI-like route decorators

- Full path validation
- UDP congestion control
- Session control

## Planned features:
- Automatic post quantum encryption



## Banger features

- JWT BASED CRYPTO HANDSHAKE IN RTT0
- Reliable & Unreliable transport mode
- UDP based hole punching
- Anti DPI complex of bypassing methods

## Run

```bash
python -m fastudp.cli server --bind 0.0.0.0 --port 9999 --psk secret123
python -m fastudp.cli client --host 127.0.0.1 --port 9999 --psk secret123 --client-id alice
```
