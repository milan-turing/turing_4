from typing import Callable, Awaitable
import os
from urllib.parse import parse_qs
from starlette.responses import JSONResponse
from starlette.types import Scope, Receive, Send
from starlette.datastructures import Headers

# configurable limits via env (fall back to conservative defaults)
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(2 * 1024)))  # 2 KB default
MAX_QUERY_PARAMS = int(os.getenv("MAX_QUERY_PARAMS", "20"))
MAX_FORM_FIELDS = int(os.getenv("MAX_FORM_FIELDS", "50"))


class LimitsMiddleware:
    """
    ASGI middleware that:
      - enforces a maximum request body size (bytes)
      - enforces a maximum number of query params
      - enforces a maximum number of form fields (for urlencoded and simple multipart heuristics)

    If a limit is exceeded, returns an immediate JSONResponse with an appropriate status.
    """
    def __init__(self, app: Callable, max_body: int = MAX_BODY_BYTES, max_qs: int = MAX_QUERY_PARAMS, max_fields: int = MAX_FORM_FIELDS):
        self.app = app
        self.max_body = max_body
        self.max_qs = max_qs
        self.max_fields = max_fields

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # quick check: query params count
        raw_qs = scope.get("query_string", b"") or b""
        if raw_qs:
            params = [p for p in raw_qs.split(b"&") if p]
            if len(params) > self.max_qs:
                resp = JSONResponse({"detail": "Too many query parameters"}, status_code=400)
                await resp(scope, receive, send)
                return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        ct = headers.get("content-type", "")

        # If content-length present and exceeds max, short-circuit
        if content_length:
            try:
                if int(content_length) > self.max_body:
                    resp = JSONResponse({"detail": "Payload too large"}, status_code=413)
                    await resp(scope, receive, send)
                    return
            except Exception:
                # ignore parse errors and proceed to guarded receive
                pass

        # wrap receive to enforce body size and to capture the whole body for form-field counting
        body_chunks = []
        received = 0
        more_body = True

        async def limited_receive():
            nonlocal received, more_body
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                received += len(body)
                if received > self.max_body:
                    # return nothing further and send error response by raising a StopIteration-style control flow:
                    # we will send a response here and then stop
                    resp = JSONResponse({"detail": "Payload too large"}, status_code=413)
                    await resp(scope, receive, send)
                    # After sending response, raise to stop further processing
                    raise RuntimeError("payload_too_large")
                body_chunks.append(body)
                more_body = message.get("more_body", False)
            return message

        # consume the body (if any) using limited_receive so we can check form field count.
        try:
            # repeatedly call limited_receive until no more_body
            while more_body:
                msg = await limited_receive()
                if not msg:
                    break
                if msg.get("more_body", False) is False:
                    break
        except RuntimeError:
            # already responded with 413 inside limited_receive
            return

        whole_body = b"".join(body_chunks) if body_chunks else b""

        # If urlencoded form, count fields
        if ct.startswith("application/x-www-form-urlencoded") and whole_body:
            try:
                parsed = parse_qs(whole_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
                if len(parsed) > self.max_fields:
                    resp = JSONResponse({"detail": "Too many form fields"}, status_code=400)
                    await resp(scope, receive, send)
                    return
            except Exception:
                # if parsing fails, be conservative and continue
                pass

        # For multipart/form-data, do a heuristic: count boundary parts via boundary marker
        if ct.startswith("multipart/form-data") and whole_body:
            # boundaries appear as b'--' + boundary bytes; count occurrences of CRLF + '--' may be tricky,
            # we use simple heuristic counting 'Content-Disposition' occurrences which typically appear per part.
            parts = whole_body.count(b"Content-Disposition:")
            if parts and parts > self.max_fields:
                resp = JSONResponse({"detail": "Too many form fields (multipart)"}, status_code=400)
                await resp(scope, receive, send)
                return

        # recreate a receive() for downstream app that will replay the captured body
        body_bytes = whole_body

        async def replay_receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        await self.app(scope, replay_receive, send)