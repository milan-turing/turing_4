from fastapi import Request

def add_security_headers(app):
    @app.middleware("http")
    async def security_headers_mw(request: Request, call_next):
        response = await call_next(request)
        # basic recommended headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        # enable and tune CSP if needed:
        # response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response