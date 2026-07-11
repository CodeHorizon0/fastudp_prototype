# fastudp

`fastudp` - UDP transport framework with a FastAPI-like routing layer
and QUIC-inspired reliability/security mechanisms.

The project implements a custom application-layer protocol over UDP. It
provides authenticated sessions, encrypted datagrams, stream
multiplexing, request/response semantics and transport management
features usually found in reliable transports.

## Architecture overview

Main components:

-   `server.py` - UDP server implementation, handshake processing,
    sessions, request routing and packet handling.
-   `client.py` - UDP client with session establishment, encrypted
    requests and stream management.
-   `codec.py` - binary protocol serializer/deserializer.
-   `security.py` - cryptographic primitives, key derivation, replay
    protection and tickets.
-   `congestion.py` - basic UDP congestion controller.
-   `routing.py` - FastAPI-like HTTP style router abstraction.
-   `pq.py` - optional post-quantum key exchange integration.

## Protocol design

Protocol version:

-   Magic: `FUDP`
-   Current version: `2`
-   Transport: UDP
-   Packet format: fixed binary header + optional path/body data.

Each packet contains:

-   message type
-   flags
-   session identifier
-   stream identifier
-   sequence number
-   request identifier
-   path length
-   payload length

## Connection establishment

The handshake uses a PSK-based authentication flow:

    CLIENT                     SERVER

    HELLO  ------------------>
                             CHALLENGE
                 <------------

    PROVE   ----------------->
                             ACK
                 <------------

During handshake:

1.  Client sends identity, timestamp, nonce and authentication data.
2.  Server validates the request and creates a challenge.
3.  Client proves knowledge of the shared secret.
4.  Both sides derive a session key.

Session keys are derived using HKDF-based key derivation.

## Encryption

Encrypted packets use:

-   ChaCha20-Poly1305 AEAD
-   unique nonce generation from stream and sequence identifiers
-   authenticated additional data

Security mechanisms:

-   replay attack protection
-   timestamp validation
-   request authentication
-   encrypted session tickets

## Reliability layer

Although UDP is unreliable, the protocol adds reliability features:

-   packet acknowledgements
-   request retries
-   sequence tracking
-   duplicate protection
-   response caching
-   stream-level multiplexing

A single session can contain multiple logical streams:

    Session
     ├── Stream 1
     │    ├── Request 1
     │    └── Request 2
     │
     ├── Stream 2
     │    └── Request 1

## Session management

Supported features:

-   session expiration
-   connection closing
-   session resumption tickets
-   authenticated address migration
-   path validation frames

Address migration allows a client to continue communication after
changing network address, provided the migration is authenticated.

## Routing layer

The server provides a lightweight FastAPI-like API:

Features:

-   HTTP-style methods:
    -   GET
    -   POST
    -   PUT
    -   DELETE
    -   PATCH
-   path parameters
-   JSON responses
-   text responses
-   binary responses

Example concept:

``` python
@app.get("/users/{id}")
async def user(request, id):
    return Response.json({"id": id})
```

## Congestion control

The project contains a UDP congestion controller:

-   tracks packets in flight
-   measures RTT
-   increases/decreases sending window
-   reacts to packet loss

This is a simplified transport algorithm and is not a full QUIC
congestion implementation.

## Optional post-quantum support

`pq.py` provides an abstraction for post-quantum key exchange.

Current behavior:

-   Uses ML-KEM-768 when `liboqs` bindings are available.
-   Falls back to a local compatibility mode when unavailable.

PQ support is currently experimental.

## Protocol message types

Implemented message classes:

  Type             Purpose
  ---------------- --------------------------------
  HELLO            Start handshake
  CHALLENGE        Server handshake challenge
  PROVE            Client authentication proof
  ACK              Packet/session acknowledgement
  REQUEST          Application request
  RESPONSE         Application response
  ERROR            Error response
  PING/PONG        Keepalive
  FRAME_ACK        Reliability acknowledgement
  PATH_CHALLENGE   Address validation
  PATH_RESPONSE    Address validation response
  CLOSE            Session termination

## Flags

Supported packet flags:

-   `ENCRYPTED` - encrypted payload
-   `RESPONSE` - response packet
-   `ERROR` - error packet
-   `COMPRESSED` - reserved compression flag
-   `0RTT` - early data support flag
-   `MIGRATED` - migrated connection flag

## Limitations

Current implementation is a prototype:

-   congestion control is simplified
-   no production-grade NAT traversal
-   no full QUIC compatibility
-   post-quantum mode requires additional validation
-   compression layer is not implemented
-   reliable/unreliable stream separation is planned

## Planned features

-   automatic hybrid classical + post-quantum handshake
-   UDP hole punching
-   improved congestion algorithms
-   unreliable datagram streams
-   advanced DPI resistance techniques
-   production-ready NAT traversal

## Running

Install dependencies:

``` bash
pip install -r requirements.txt
```

Start server:

``` bash
python -m fastudp.cli server --bind 0.0.0.0 --port 9999 --psk secret123
```

Start client:

``` bash
python -m fastudp.cli client --host 127.0.0.1 --port 9999 --psk secret123 --client-id alice
```

## Security model

The protocol currently assumes:

-   client and server share a PSK
-   PSK distribution happens through a trusted channel
-   cryptographic identity is based on possession of the shared secret

The protocol provides confidentiality and authentication after session
establishment, but it is not intended as a replacement for standardized
protocols such as QUIC/TLS without further security review.
