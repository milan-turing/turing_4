import os
from fastapi.middleware.cors import CORSMiddleware

def configure_cors(app):
    origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    # TODO : in production, set CORS_ORIGINS to the actual allowed origins
    if not origins:
        origins = ["http://localhost:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        max_age=86400,
    )