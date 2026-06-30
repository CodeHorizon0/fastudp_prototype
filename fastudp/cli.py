from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any

from .client import FastUDPClient
from .server import FastUDPServer


async def run_server(bind: str, port: int, psk: str, log_level: str) -> None:
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = FastUDPServer(psk=psk, bind=bind, port=port)

    @app.get("/ping")
    async def ping(request: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "session_id": request.transport.session_id,
            "client_id": request.transport.client_id,
        }

    @app.get("/conn")
    async def conn(request: Any) -> dict[str, Any]:
        return {
            "session_id": request.transport.session_id,
            "client_id": request.transport.client_id,
        }

    @app.post("/echo/{name}")
    async def echo(request: Any, name: str) -> dict[str, Any]:
        try:
            payload = request.json()
        except Exception:
            payload = request.text()
        return {
            "name": name,
            "payload": payload,
            "query": request.query_params,
            "stream_id": request.stream_id,
            "request_id": request.request_id,
        }

    await app.serve()


async def run_client(host: str, port: int, psk: str, client_id: str) -> None:
    client = FastUDPClient(
        host=host,
        port=port,
        psk=psk,
        client_id=client_id,
    )

    session = await client.connect()
    ch1 = session.channel(1)
    ch2 = session.channel(2)

    responses = await asyncio.gather(
        ch1.post("/echo/test", json_data={"index": 1}),
        ch2.post("/echo/second", json_data={"index": 2}),
        ch1.get("/ping"),
    )
    for response in responses:
        print(response.status_code, response.json_body())

    for i in range(3):
        r = await ch1.post("/echo/test", json_data={"index": i, "kind": "reused"})
        print(r.status_code, r.json_body())

    await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="FastUDP transport layer")
    sub = parser.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("server")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=9999)
    s.add_argument("--psk", required=True)
    s.add_argument("--log-level", default="INFO")

    c = sub.add_parser("client")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--port", type=int, default=9999)
    c.add_argument("--psk", required=True)
    c.add_argument("--client-id", required=True)

    args = parser.parse_args()
    if args.mode == "server":
        asyncio.run(run_server(args.bind, args.port, args.psk, args.log_level))
    else:
        asyncio.run(run_client(args.host, args.port, args.psk, args.client_id))


if __name__ == "__main__":
    main()
