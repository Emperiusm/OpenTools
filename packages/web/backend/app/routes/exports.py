"""Data export and import API routes."""

import io
import json

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from starlette.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.dependencies import get_db, get_current_user
from app.models import User

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])


class ExportRequest(BaseModel):
    engagement_id: str
    options: Optional[dict] = None


@router.post("/json")
async def export_json(
    body: ExportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        from opentools.findings import export_json as do_export_json

        data = do_export_json(body.engagement_id)
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{body.engagement_id}.json"'
            },
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Export not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"JSON export failed: {exc}")


@router.post("/zip")
async def export_zip(
    body: ExportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        from opentools.engagement.export import export_engagement

        bundle = export_engagement(body.engagement_id)
        return StreamingResponse(
            io.BytesIO(bundle),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{body.engagement_id}.zip"'
            },
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Export not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ZIP export failed: {exc}")


@router.post("/sarif")
async def export_sarif(
    body: ExportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        from opentools.findings import export_sarif as do_export_sarif

        data = do_export_sarif(body.engagement_id)
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{body.engagement_id}.sarif"'
            },
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Export not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SARIF export failed: {exc}")


@router.post("/stix")
async def export_stix(
    body: ExportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        from opentools.stix_export import export_stix as do_export_stix

        data = do_export_stix(body.engagement_id)
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{body.engagement_id}.stix.json"'
            },
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="STIX export not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"STIX export failed: {exc}")


@router.post("/import")
async def import_engagement(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        from opentools.engagement.export import import_engagement as do_import

        contents = await file.read()
        result = do_import(contents)
        return {"status": "imported", "detail": result}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Import not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Import failed: {exc}")
