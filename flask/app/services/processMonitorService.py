from datetime import datetime
from zoneinfo import ZoneInfo

from app import db  # 使用已导入的 db
from ..models.processMonitorModel import LogMonitor


# 获取所有条目
def get_all_entries():
    entries = db.query(LogMonitor).all()
    return [entry.to_dict() for entry in entries]


# 根据 ID 获取条目
def get_entry_by_id(entry_id: str):
    entry = db.query(LogMonitor).filter_by(id=entry_id).first()
    return entry.to_dict() if entry else None


# 创建新条目
def create_entry(data: dict):
    new_entry = LogMonitor(**data)
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    return new_entry.to_dict()


# 更新条目
def update_entry(entry_id: str, data: dict):
    entry = db.query(LogMonitor).filter_by(id=entry_id).first()
    if not entry:
        return None
    for key, value in data.items():
        setattr(entry, key, value)
    entry.update_at = datetime.now(ZoneInfo('Asia/Shanghai'))
    db.commit()
    db.refresh(entry)
    return entry.to_dict()


# 删除条目
def delete_entry(entry_id: str):
    entry = db.query(LogMonitor).filter_by(id=entry_id).first()
    if not entry:
        return False
    db.delete(entry)
    db.commit()
    return True


# 挂起条目
def suspend_entry(entry_id: str, suspend_until: datetime):
    entry = db.query(LogMonitor).filter_by(id=entry_id).first()
    if not entry:
        return None
    entry.is_suspended = True
    entry.ignore_alert_until = suspend_until
    entry.update_at = datetime.now(ZoneInfo('Asia/Shanghai'))
    db.commit()
    db.refresh(entry)
    return entry.to_dict()


# 检查挂起状态
def check_suspend_status():
    entries = db.query(LogMonitor).all()
    for entry in entries:
        if entry.is_suspended and entry.ignore_alert_until:
            if datetime.now(ZoneInfo('Asia/Shanghai')) > entry.ignore_alert_until:
                entry.is_suspended = False
                entry.update_at = datetime.now(ZoneInfo('Asia/Shanghai'))
                db.commit()
