from fastapi import APIRouter, Depends, HTTPException
from app.auth import require_auth
from app.services import notification_service as svc

router = APIRouter(prefix="/api/notifications", tags=["notifications"], dependencies=[Depends(require_auth)])


@router.get("")
async def list_notifications(unread: bool = False, user: dict = Depends(require_auth)):
    return await svc.list_notifications(user["username"], unread_only=unread)


@router.post("/read-all")
async def read_all(user: dict = Depends(require_auth)):
    return {"updated": await svc.mark_all_read(user["username"])}


@router.post("/{notif_id}/read")
async def read_one(notif_id: str, user: dict = Depends(require_auth)):
    if not await svc.mark_read(user["username"], notif_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"ok": True}
