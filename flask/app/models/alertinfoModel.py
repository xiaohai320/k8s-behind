from datetime import datetime
from zoneinfo import ZoneInfo

from app import db
class AlertsInfo(db.Model):
    __tablename__ = 'alerts_info'
    fingerprint = db.Column(db.String(64), primary_key=True, nullable=False)
    status = db.Column(db.Enum('firing', 'resolved'), nullable=False)
    startsAt = db.Column(db.DateTime, nullable=False)
    endsAt = db.Column(db.DateTime, nullable=True)
    alertname = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(50), nullable=True)
    instance = db.Column(db.String(255), nullable=True)
    job = db.Column(db.String(255), nullable=True)
    generatorURL = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))
    updated_at = db.Column(db.DateTime, onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))
    suspend_until= db.Column(db.DateTime,nullable=True)
    suspend_reason = db.Column(db.Text, nullable=True)
    suspend_status= db.Column(db.Enum('suspended', 'unsuspended','None'),default='None',nullable=True)
    def to_dict(self):
        """将对象转换为字典"""
        return {
            'fingerprint': self.fingerprint,
            'status': self.status,
            'startsAt': self.startsAt.isoformat() if self.startsAt else None,
            'endsAt': self.endsAt.isoformat() if self.endsAt else None,
            'alertname': self.alertname,
            'description': self.description,
            'severity': self.severity,
            'instance': self.instance,
            'job': self.job,
            'generatorURL': self.generatorURL,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'suspend_until': self.suspend_until.isoformat() if self.suspend_until else None,
            'suspend_reason': self.suspend_reason,
            'suspend_status': self.suspend_status,
        }