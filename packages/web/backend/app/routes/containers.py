"""Container management API routes."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.dependencies import get_current_user
from app.models import User

router = APIRouter(prefix="/api/v1/containers", tags=["containers"])


class ContainerAction(BaseModel):
    service: Optional[str] = None


@router.get("")
async def container_status(
    user: User = Depends(get_current_user),
):
    try:
        from opentools.containers import ContainerManager
        from opentools.config import ConfigLoader

        config = ConfigLoader().load()
        manager = ContainerManager(config)
        status = manager.status()
        return {"containers": status}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Container management not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Docker not available: {exc}")


@router.post("/start")
async def container_start(
    body: ContainerAction,
    user: User = Depends(get_current_user),
):
    try:
        from opentools.containers import ContainerManager
        from opentools.config import ConfigLoader

        config = ConfigLoader().load()
        manager = ContainerManager(config)
        result = manager.start(service=body.service)
        return {"status": "started", "detail": result}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Container management not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Docker not available: {exc}")


@router.post("/stop")
async def container_stop(
    body: ContainerAction,
    user: User = Depends(get_current_user),
):
    try:
        from opentools.containers import ContainerManager
        from opentools.config import ConfigLoader

        config = ConfigLoader().load()
        manager = ContainerManager(config)
        result = manager.stop(service=body.service)
        return {"status": "stopped", "detail": result}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Container management not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Docker not available: {exc}")


@router.post("/restart")
async def container_restart(
    body: ContainerAction,
    user: User = Depends(get_current_user),
):
    try:
        from opentools.containers import ContainerManager
        from opentools.config import ConfigLoader

        config = ConfigLoader().load()
        manager = ContainerManager(config)
        result = manager.restart(service=body.service)
        return {"status": "restarted", "detail": result}
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Container management not available (opentools CLI not installed)",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Docker not available: {exc}")
