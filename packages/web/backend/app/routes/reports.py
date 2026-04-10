"""Report generation API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.models import User

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


class ReportGenerateRequest(BaseModel):
    engagement_id: str
    template: str = "default"
    format: str = "markdown"
    options: Optional[dict] = None


@router.post("/generate")
async def generate_report(
    body: ReportGenerateRequest,
    user: User = Depends(get_current_user),
):
    try:
        from opentools.reports import ReportGenerator

        generator = ReportGenerator()
        result = generator.generate(
            engagement_id=body.engagement_id,
            template=body.template,
            output_format=body.format,
            options=body.options or {},
        )
        return {"content": result, "format": body.format}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Report generation not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")


@router.get("/templates")
async def list_templates(
    user: User = Depends(get_current_user),
):
    try:
        from opentools.reports import ReportGenerator

        generator = ReportGenerator()
        templates = generator.list_templates()
        return {"items": templates}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Report generation not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list templates: {exc}")
