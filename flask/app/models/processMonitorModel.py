
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Text
from app import db
from zoneinfo import ZoneInfo


class LogMonitor(db.Model):
    __tablename__ = 'log_monitor'

    id = Column(String(36), primary_key=True)  # 主键
    hostname = Column(String(255), nullable=False)  # 主机名
    process_name = Column(String(255), nullable=False)  # 进程名
    update_at = Column(DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')), onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))  # 更新时间
    create_at = Column(DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))  # 创建时间
    process_status = Column(String(50), nullable=False)  # 进程状态
    monitor_start_time = Column(String(8), nullable=False)  # 监控开始时间
    monitor_end_time = Column(String(8), nullable=False)  # 监控结束时间
    run_log_keywords = Column(Text, nullable=False)  # 运行日志过滤关键字
    error_log_keywords = Column(Text, nullable=False)  # 错误日志过滤关键字
    log_path = Column(Text, nullable=False)  # 日志路径
    ignore_alert_until = Column(DateTime, nullable=True)  # 忽略告警结束时间（挂起到期时间）
    alert_log_params = Column(Text, nullable=True)  # 告警日志参数（错误日志中出现的关键词）
    is_suspended = Column(Boolean, default=False)  # 是否挂起（0/1）
    is_alerted = Column(Boolean, default=False)  # 是否告警（0/1）
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
            "run_log_keywords": self.run_log_keywords,
            "error_log_keywords": self.error_log_keywords,
            "log_path": self.log_path,
            "ignore_alert_until": self.ignore_alert_until.isoformat() if self.ignore_alert_until else None,
            "alert_log_params": self.alert_log_params,
            "is_suspended": self.is_suspended,
            "is_alerted": self.is_alerted,
        }