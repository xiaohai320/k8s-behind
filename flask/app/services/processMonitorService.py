import os
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo

from apscheduler.triggers.date import DateTrigger
from dateutil import parser
from fabric import Connection
from flask import g, current_app
from idna.idnadata import scripts
from sqlalchemy.exc import SQLAlchemyError

from app import db, scheduler  # 使用已导入的 db
from .sshServices import add_log
from ..models.linuxUserHostModel import LinuxHost, LinuxUser
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
    # 提取需要入库的字段
    # 提取需要入库的字段
    hostname = data.get('hostname')
    process_name = data.get('process_name')
    process_status = data.get('process_status')
    monitor_start_time = data.get('monitor_start_time')
    monitor_end_time = data.get('monitor_end_time')
    log_path = data.get('current_directory')
    script_name=data.get('script_name')
    # 查询是否存在具有相同 hostname 和 process_name 的记录
    existing_entry = LogMonitor.query.filter_by(hostname=hostname, process_name=process_name).first()
    if existing_entry:
        # 更新现有记录
        existing_entry.process_status = process_status
        existing_entry.monitor_start_time = monitor_start_time
        existing_entry.monitor_end_time = monitor_end_time
        existing_entry.log_path = log_path
        existing_entry.script_name=script_name
        db.session.commit()
        new_entry = existing_entry
    else:
        # 创建新的 LogMonitor 实例
        new_entry = LogMonitor(hostname=hostname, process_name=process_name, process_status=process_status,
                               monitor_start_time=monitor_start_time, script_name=script_name,monitor_end_time=monitor_end_time, log_path=log_path)
        db.session.add(new_entry)
        db.session.commit()
    # 处理 logs 字段中的 errorLogs 和 runLogs 数组
    if 'logs' in data:
        logs = data['logs']
        base_dir = os.path.abspath(os.path.dirname(__file__))  # 获取当前脚本所在目录
        log_filename = os.path.join(base_dir, '..', 'file', f"{hostname}_{process_name}.log")
        with open(log_filename, 'w') as log_file:
            for log in logs:
                log_file.write(log + '\n')
    return new_entry.to_dict()
def read_log_from_host(hostname, script_name, log_path,log_type):
    try:
        # 获取主机信息
        host = LinuxHost.query.filter_by(hostname=hostname).first()
        if not host:
            raise ValueError("Host not found")
        # 获取用户信息
        user = LinuxUser.query.filter_by(username="root", host_id=host.id).first()
        if not user:
            raise ValueError("User not found")

        # 创建 SSH 连接
        conn = Connection(
            host=host.ip_address,
            user=user.username,
            connect_kwargs={"password": user.password}
        )
        # 读取日志文件内容
        result = conn.run(f"tail -n 50 {log_path}/{script_name}.{log_type}", hide=True)
        if result.ok:
            return result.stdout
        else:
            return None
    except Exception as e:
        current_app.logger.error(f"Error reading log from host: {e}")
        return None

