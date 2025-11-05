# app/api/routes/products.py
import os
import json
from fastapi import UploadFile, File
from app.config import settings
from app.utils.images import save_image_upload, list_product_images, delete_product_image


from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.api.deps import get_db, get_current_active_user, require_admin
from app.api.schemas.product import ProductCreate, ProductOut, ProductUpdate
from app.database import FileBackedDB
from datetime import datetime

router = APIRouter(prefix="/api/products", tags=["products"])

# db: FileBackedDB = get_db()


def _row_to_product_out(row: dict) -> ProductOut:
    # Ensure fields expected by ProductOut exist and have reasonable defaults
    return ProductOut(
        id=row.get("id") or row.get("product_id"),
        title=row.get("title") or "",
        description=row.get("description") or "",
        category=row.get("category") or "general",
        price=float(row.get("price") or 0.0),
        stock=int(float(row.get("stock") or 0)),
        image_filename=row.get("image_filename") or row.get("image") or None,
        created_by=row.get("created_by") or None,
        created_at=row.get("created_at") or None,
    )


@router.get("/", response_model=List[ProductOut])
def list_products(
    q: Optional[str] = Query(None, description="search query (title)"),
    limit: int = 100,
    offset: int = 0,
    db: FileBackedDB = Depends(get_db),
):
    """
    List products. Supports optional title substring search via `q`.
    """
    all_rows = db.list_records("products")
    results = []
    for r in all_rows:
        title = str(r.get("title") or "")
        if q:
            if q.lower() not in title.lower():
                continue
        results.append(_row_to_product_out(r))
    # apply offset/limit
    return results[offset : offset + limit]


@router.get("/{product_id}", response_model=ProductOut)
def get_product(product_id: str, db: FileBackedDB = Depends(get_db)):
    row = db.get_record("products", "id", product_id) or db.get_record("products", "product_id", product_id)
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    return _row_to_product_out(row)


@router.post("/", response_model=ProductOut, dependencies=[Depends(require_admin)])
def create_product(payload: ProductCreate, current_user: dict = Depends(get_current_active_user), db: FileBackedDB = Depends(get_db)):
    """
    Create a new product (admin only). `created_by` is set to current_user['username'].
    """
    data = payload.model_dump()
    data["created_by"] = current_user.get("username")
    data["created_at"] = datetime.utcnow().isoformat(sep=" ")
    saved = db.create_record("products", data, id_field="id")
    return _row_to_product_out(saved)


@router.put("/{product_id}", response_model=ProductOut, dependencies=[Depends(require_admin)])
def update_product(product_id: str, payload: ProductUpdate, db: FileBackedDB = Depends(get_db)):
    # find product
    row = db.get_record("products", "id", product_id) or db.get_record("products", "product_id", product_id)
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    updates = payload.model_dump(exclude_unset=True)
    updated = db.update_record("products", "id", product_id, updates)
    if not updated:
        # maybe update by product_id key
        updated = db.update_record("products", "product_id", product_id, updates)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update")
    return _row_to_product_out(updated)


@router.delete("/{product_id}", dependencies=[Depends(require_admin)])
def delete_product(product_id: str, db: FileBackedDB = Depends(get_db)):
    # try by id then product_id
    ok = db.delete_record("products", "id", product_id)
    if not ok:
        ok = db.delete_record("products", "product_id", product_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}

@router.post("/{product_id}/upload-image", dependencies=[Depends(require_admin)])
async def upload_product_image(product_id: str, file: UploadFile = File(...), db: FileBackedDB = Depends(get_db)):
    """
    Upload an image for a product (admin only).
    Saves original + variants and appends the filename(s) to product.image_filenames (JSON list).
    """
    # ensure product exists
    row = db.get_record("products", "id", product_id) or db.get_record("products", "product_id", product_id)
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")

    # Basic validation: protect against filename injection and enforce content-type + extension
    filename = getattr(file, "filename", "") or ""
    # reject empty or obviously malicious filenames
    if not filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if len(filename) > 120:
        raise HTTPException(status_code=400, detail="Filename too long")

    # validate extension
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    allowed_exts = {".jpg", ".jpeg", ".png", ".webp"}
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail="Unsupported file extension")

    # validate content-type
    allowed_mimes = {"image/jpeg", "image/png", "image/webp"}
    content_type = getattr(file, "content_type", "") or ""
    if content_type not in allowed_mimes:
        raise HTTPException(status_code=400, detail="Unsupported content type")

    # ensure image dir exists
    image_dir = settings.image_dir
    # save file and generate thumbnails
    saved = await save_image_upload(file, product_id, image_dir)
    # update product record: append original filename to image_filenames list stored as JSON
    cur = row.get("image_filenames") or row.get("image_filename") or ""
    try:
        cur_list = json.loads(cur) if cur else []
        if not isinstance(cur_list, list):
            cur_list = [cur] if cur else []
    except Exception:
        cur_list = [cur] if cur else []

    cur_list.append(saved["original"])
    # optionally also append variants if desired:
    # cur_list.extend(saved["variants"])
    updates = {"image_filename": json.dumps(cur_list)}
    db.update_record("products", "id", product_id, updates)
    # Build accessible URLs
    urls = [f"/{settings.image_dir.rstrip('/')}/products/{product_id}/{fname}" for fname in cur_list]
    return {"ok": True, "filenames": cur_list, "urls": urls, "saved": saved}


@router.get("/{product_id}/images", response_model=List[str])
def get_product_images(product_id: str, db: FileBackedDB = Depends(get_db)):
    """
    List image URLs for a product (public).
    """
    row = db.get_record("products", "id", product_id) or db.get_record("products", "product_id", product_id)
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    image_dir = settings.image_dir
    cur = row.get("image_filenames") or row.get("image_filename") or ""
    try:
        cur_list = json.loads(cur) if cur else []
        if not isinstance(cur_list, list):
            cur_list = [cur] if cur else []
    except Exception:
        cur_list = [cur] if cur else []

    urls = [f"/{image_dir.rstrip('/')}/products/{product_id}/{fname}" for fname in cur_list]
    return urls


@router.delete("/{product_id}/images/{filename}", dependencies=[Depends(require_admin)])
def delete_product_image_route(product_id: str, filename: str, db: FileBackedDB = Depends(get_db)):
    """
    Delete an image file and remove from product's image_filenames array (admin only).
    """
    row = db.get_record("products", "id", product_id) or db.get_record("products", "product_id", product_id)
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")

    image_dir = settings.image_dir
    ok = delete_product_image(image_dir, product_id, filename)
    if not ok:
        raise HTTPException(status_code=404, detail="File not found or could not be deleted")

    # remove from product record
    cur = row.get("image_filenames") or row.get("image_filename") or ""
    try:
        cur_list = json.loads(cur) if cur else []
        if not isinstance(cur_list, list):
            cur_list = [cur] if cur else []
    except Exception:
        cur_list = [cur] if cur else []

    cur_list = [f for f in cur_list if f != filename]
    db.update_record("products", "id", product_id, {"image_filenames": json.dumps(cur_list)})
    return {"ok": True, "remaining": cur_list}
