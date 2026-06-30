from __future__ import annotations

import inspect
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Pattern, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

from .exceptions import ProtocolError, RouteNotFound


@dataclass(slots=True)
class Route:
    method: str
    path_template: str
    regex: Pattern[str]
    param_names: Tuple[str, ...]
    handler: Callable[..., Awaitable[Any] | Any]


@dataclass(slots=True)
class Request:
    app: "FastUDPServer"
    transport: "TransportSessionProxy"
    method: str
    path: str
    raw_path: str
    query_params: Dict[str, str]
    path_params: Dict[str, str]
    body: bytes
    stream_id: int
    request_id: int

    def text(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self.body.decode(encoding, errors)

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass(slots=True)
class Response:
    status_code: int = 200
    content_type: str = "application/octet-stream"
    body: bytes = b""

    @classmethod
    def json(cls, data: Any, status_code: int = 200) -> "Response":
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return cls(status_code=status_code, content_type="application/json", body=body)

    @classmethod
    def text(cls, data: str, status_code: int = 200) -> "Response":
        return cls(status_code=status_code, content_type="text/plain; charset=utf-8", body=data.encode("utf-8"))

    @classmethod
    def bytes(cls, data: bytes, status_code: int = 200, content_type: str = "application/octet-stream") -> "Response":
        return cls(status_code=status_code, content_type=content_type, body=data)

    def json_body(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def text_body(self) -> str:
        return self.body.decode("utf-8")


class RouteTable:
    def __init__(self) -> None:
        self._routes: List[Route] = []

    def add(self, method: str, path: str, handler: Callable[..., Any]) -> Callable[..., Any]:
        compiled, param_names = self._compile_path(path)
        route = Route(
            method=method.upper(),
            path_template=path,
            regex=compiled,
            param_names=param_names,
            handler=handler,
        )
        self._routes.append(route)
        return handler

    def match(self, method: str, path: str) -> Tuple[Callable[..., Any], Dict[str, str]]:
        method = method.upper()
        for route in self._routes:
            if route.method != method:
                continue
            match = route.regex.fullmatch(path)
            if match is not None:
                return route.handler, match.groupdict()
        raise RouteNotFound(f"route not found: {method} {path}")

    @staticmethod
    def _compile_path(path: str) -> Tuple[Pattern[str], Tuple[str, ...]]:
        if not path.startswith("/"):
            raise ValueError("route path must start with /")
        param_names: List[str] = []
        regex: List[str] = ["^"]
        i = 0
        while i < len(path):
            ch = path[i]
            if ch == "{":
                end = path.find("}", i + 1)
                if end == -1:
                    raise ValueError(f"unclosed parameter in route: {path}")
                name = path[i + 1:end].strip()
                if not name.isidentifier():
                    raise ValueError(f"invalid parameter name: {name}")
                param_names.append(name)
                regex.append(fr"(?P<{name}>[^/]+)")
                i = end + 1
                continue
            if ch in ".^$+*?[]\\|()":
                regex.append("\\" + ch)
            else:
                regex.append(ch)
            i += 1
        regex.append("$")
        return re.compile("".join(regex)), tuple(param_names)


class FastUDPApp:
    def __init__(self) -> None:
        self.router = RouteTable()

    def route(self, path: str, methods: Sequence[str]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            for method in methods:
                self.router.add(method, path, handler)
            return handler

        return decorator

    def get(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, ["GET"])

    def post(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, ["POST"])

    def put(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, ["PUT"])

    def delete(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, ["DELETE"])

    def patch(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, ["PATCH"])


class TransportSessionProxy:
    def __init__(self, session: "SessionState", server: "FastUDPServer") -> None:
        self.session = session
        self.server = server

    @property
    def session_id(self) -> int:
        return self.session.session_id

    @property
    def client_id(self) -> str:
        return self.session.client_id


def build_handler_kwargs(handler: Callable[..., Any], request: Request) -> Dict[str, Any]:
    signature = inspect.signature(handler)
    kwargs: Dict[str, Any] = {}
    for name, param in signature.parameters.items():
        if name == "request":
            kwargs[name] = request
            continue
        if name in request.path_params:
            kwargs[name] = convert_param(request.path_params[name], param.annotation)
            continue
        if name in request.query_params:
            kwargs[name] = convert_param(request.query_params[name], param.annotation)
            continue
        if param.default is not inspect._empty:
            continue
        raise ProtocolError(f"missing required parameter: {name}")
    return kwargs


def convert_param(value: str, annotation: Any) -> Any:
    if annotation in (inspect._empty, str, Any):
        return value
    if annotation is int:
        return int(value)
    if annotation is float:
        return float(value)
    if annotation is bool:
        return value.lower() in ("1", "true", "yes", "on")
    return value


def normalize_response(result: Any) -> Response:
    if isinstance(result, Response):
        return result
    if result is None:
        return Response(status_code=204, content_type="application/octet-stream", body=b"")
    if isinstance(result, bytes):
        return Response.bytes(result)
    if isinstance(result, str):
        return Response.text(result)
    return Response.json(result)


def split_path(path: str) -> Tuple[str, Dict[str, str]]:
    parsed = urlsplit(path)
    query_raw = parse_qs(parsed.query, keep_blank_values=True)
    query_params = {key: values[-1] for key, values in query_raw.items() if values}
    return parsed.path or "/", query_params
