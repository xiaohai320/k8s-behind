
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Text
from app import db
from zoneinfo import ZoneInfo


class LogMonitor(db.Model):
    __tablename__ = 'log_monitor'
    id = db.Column(db.Integer, primary_key=True)
    hostname = Column(String(255), nullable=True)  # 主机名
    process_name = Column(String(255), nullable=True)  # 进程名
    update_at = Column(DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')), onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))  # 更新时间
    create_at = Column(DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))  # 创建时间
    process_status = Column(String(50), nullable=True)  # 进程状态
    monitor_start_time = Column(String(8), nullable=True)  # 监控开始时间
    monitor_end_time = Column(String(8), nullable=True)  # 监控结束时间
    log_path = Column(Text, nullable=True)  # 日志路径
    script_name= Column(String(255), nullable=True)
    def to_dict(self):
        return {
            "id": self.id,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "update_at": self.update_at.isoformat() if self.update_at else None,
            "create_at": self.create_at.isoformat() if self.create_at else None,
            "process_status": self.process_status,
            "monitor_start_time": self.monitor_start_time,
            "monitor_end_time": self.monitor_end_time,
            "log_path": self.log_path,
            "script_name": self.script_name
        }