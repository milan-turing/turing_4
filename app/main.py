# app/main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
import os
from contextlib import asynccontextmanager

from app.config import settings
from app.database import db
from app.api.routes import auth as auth_routes
from app.api.routes import products as product_routes
from app.api.routes import orders as order_routes
from app.api.routes import wishlist as wishlist_routes
from app.api.routes import reviews as reviews_routes
from app.api.routes import cart as cart_routes
from app.api.deps import oauth2_scheme
from app.middleware.cors_config import configure_cors
from app.middleware.security_headers import add_security_headers


logger = logging.getLogger("uvicorn.error")
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context: run startup checks before the app starts serving,
    and allow for clean shutdown actions if needed later.
    """
    # --- startup logic ---
    try:
        # ensure DB module is importable
        _ = db
    except Exception as e:
        logger.warning("Database module import problem at startup: %s", e)

    # Check for users table (file). If missing, warn the developer to run init script.
    try:
        users_path = db._file_path("users")
        if not users_path.exists():
            logger.warning(
                "Users file not found at %s — please create users table (e.g. run scripts/init_users_db.py) or register an admin.",
                users_path,
            )
        else:
            logger.info("Found users file: %s", users_path)
    except Exception as e:
        logger.warning("Error while checking users file at startup: %s", e)

    yield
    # --- shutdown logic (if needed) ---
    logger.info("Shutting down Decor Store API")
app = FastAPI(title="Decor Store API", version="0.1.0", lifespan=lifespan)
configure_cors(app)
add_security_headers(app)

# Mount a static directory if present (for images / assets)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates") if os.path.isdir("templates") else None

# Include API routers
app.include_router(auth_routes.router)
app.include_router(product_routes.router)
app.include_router(order_routes.router)
app.include_router(wishlist_routes.router)
app.include_router(reviews_routes.router)
app.include_router(cart_routes.router)


@app.get("/", tags=["root"])
async def root():
    return {"status": "ok", "service": "Decor Store API"}

# Small debug helper - only for development
@app.get("/debug/openapi-paths")
def debug_paths():
    """
    Return the list of registered OpenAPI paths (helpful for debugging route registration).
    Remove or secure this in production.
    """
    return {"paths": sorted(list(app.openapi()["paths"].keys()))}


# Simple template-based admin health page (if templates exist)
if templates:
    @app.get("/admin", include_in_schema=False)
    async def admin_index(request: Request):
        """
        Minimal admin landing page (developer convenience). The page itself does not
        perform auth checks — the APIs it calls should. Use proper auth in production.
        """
        return templates.TemplateResponse("admin.html", {"request": request})
