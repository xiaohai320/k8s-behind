import re
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo

from django.core.cache import cache
from flask import g
from sqlalchemy import or_

from app.models.linuxUserHostModel import LinuxHost,LinuxUser
from fabric import Connection
from app import db
from app.models.scriptTaskModel import ScriptTask,ScriptLog


def list_all_hosts():
    hosts = LinuxHost.query.all()
    return hosts

def list_hosts(page=1, per_page=10,querySearch=None):
    query = LinuxHost.query
    if querySearch:
        query = query.filter(
            or_(
                LinuxHost.hostname.ilike(f'%{querySearch}%'),
                LinuxHost.ip_address.ilike(f'%{querySearch}%')
            )
        )
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    hosts = [hosts.to_dict() for hosts in pagination.items]
    response_data = {
        'items': hosts,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    }
    return response_data

def get_host(host_id):
    host = LinuxHost.query.get(host_id)
    return host

def create_host(hostname, ip_address,port=22, description=None):
    new_host = LinuxHost(hostname=hostname, ip_address=ip_address, port=port,description=description)
    db.session.add(new_host)
    db.session.commit()
    return new_host

def update_host(host_id, hostname=None, ip_address=None,port=22, description=None):
    host = LinuxHost.query.get(host_id)
    if not host:
        return None
    if hostname:
        host.hostname = hostname
    if ip_address:
        host.ip_address = ip_address
    if port:
        host.port = port
    if description:
        host.description = description
    db.session.commit()
    return host

def delete_host(host_id):
    host = LinuxHost.query.get(host_id)
    if not host:
        return None
    db.session.delete(host)
    db.session.commit()
    return host

def list_users():
    users = LinuxUser.query.all()
    return users

def get_users_by_host(host_id):
    users = LinuxUser.query.filter_by(host_id=host_id).all()
    return users

def get_user(user_id):
    user = LinuxUser.query.get(user_id)
    return user

def create_user(username, password, host_id):
    new_user = LinuxUser(username=username, password=password, host_id=host_id)
    db.session.add(new_user)
    db.session.commit()
    return new_user

def update_user(user_id, username=None, password=None, host_id=None):
    user = LinuxUser.query.get(user_id)
    if not user:
        return None
    if username:
        user.username = username
    if password:
        user.password = password
    if host_id:
        user.host_id = host_id
    db.session.commit()
    return user

def delete_user(user_id):
    user = LinuxUser.query.get(user_id)
    if not user:
        return None
    db.session.delete(user)
    db.session.commit()
    return user

def create_script_task(name, content, author):
    """创建一个新的脚本任务"""
    try:
        task = ScriptTask(
            name=name,
            content=content,
            author=author
        )
        db.session.add(task)
        db.session.commit()
        return task
    except Exception as e:
        db.session.rollback()
        raise e

def get_script_task(task_id):
    """获取指定ID的脚本任务"""
    return ScriptTask.query.get(task_id)

def list_all_script_tasks():
    return ScriptTask.query.all()

def list_script_tasks(page=1, per_page=10,script_name=None):
    """列出所有的脚本任务"""
    query = ScriptTask.query
    if script_name:
        query = query.filter(ScriptTask.name.ilike(f'%{script_name}%'))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    tasks = [tasks.to_dict() for tasks in pagination.items]
    response_data = {
        'items': tasks,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    }
    return response_data

def update_script_task(task_id, name=None, content=None):
    """更新指定ID的脚本任务"""
    try:
        task = ScriptTask.query.get(task_id)
        if not task:
            return None
        if name is not None:
            task.name = name
        if content is not None:
            task.content = content
        task.updated_at = datetime.now(ZoneInfo('Asia/Shanghai'))
        db.session.commit()
        return task
    except Exception as e:
        db.session.rollback()
        raise e

def delete_script_task(task_id):
    """删除指定ID的脚本任务"""
    try:
        task = ScriptTask.query.get(task_id)
        if not task:
            return False
        db.session.delete(task)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        raise e
def updateLast_RunInfo(task_id):
    task = ScriptTask.query.get(task_id)
    task.last_runtime = datetime.now(ZoneInfo('Asia/Shanghai'))
    task.last_executor ="Name:"+g.current_user["user_name"]+"Account:"+g.current_user["user_account"]
    db.session.commit()

def add_log(script_name, host_info, executor_role, status, result):
    new_log = ScriptLog(
        script_name=script_name,
        host_info=host_info,
        executor_role=executor_role,
        status=status,
        result=result
    )
    db.session.add(new_log)
    db.session.commit()
    return new_log

def delete_log(log_id):
    log = ScriptLog.query.get(log_id)
    if log:
        db.session.delete(log)
        db.session.commit()
        return True
    return False

def get_logs_with_pagination(page, per_page, script_name=None, host_info=None, executor_role=None, status=None):
    query = ScriptLog.query
    if script_name:
        query = query.filter(ScriptLog.script_name.ilike(f'%{script_name}%'))
    if host_info:
        query = query.filter(ScriptLog.host_info.ilike(f'%{host_info}%'))
    if executor_role:
        query = query.filter(ScriptLog.executor_role.ilike(f'%{executor_role}%'))
    if status:
        query = query.filter(ScriptLog.status.ilike(f'%{status}%'))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = [log.to_dict() for log in pagination.items]
    response_data = {
        'items': logs,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    }
    return response_data
def execute_script_once(host_id, user_id, script_task_id):
    # 获取主机和用户信息
    host = LinuxHost.query.get(host_id)
    user = LinuxUser.query.get(user_id)
    script_task = ScriptTask.query.get(script_task_id)
    content = script_task.content.replace('\r\n', '\n')
    if not host or not user or not script_task:
        raise ValueError("Host, User, or ScriptTask not found")
    # 创建 SSH 连接
    try:
        conn = Connection(
            host=host.ip_address,
            user=user.username,
            connect_kwargs={"password": user.password}
        )
        # 执行脚本
        result = conn.run(content, hide=True)
        updateLast_RunInfo(script_task_id)
        add_log(script_name=script_task.name, host_info=f"{host.hostname}:{user.username}@{host.ip_address}",
                executor_role=f"{g.current_user["user_account"]}", status=f"{result.ok}",
                result=result.stdout + result.stderr)
        return result
    except Exception as e:
        updateLast_RunInfo(script_task_id)
        add_log(script_name=script_task.name, host_info=f"{host.hostname}:{user.username}@{host.ip_address}",
                executor_role=f"{g.current_user["user_account"]}", status="false",
                result=e)

def cron_script(host_id, user_id, script_task_id,cron_cycle):
    # 获取主机和用户信息
    host = LinuxHost.query.get(host_id)
    user = LinuxUser.query.get(user_id)
    script_task = ScriptTask.query.get(script_task_id)
    #cron正则表达式
    cron_pattern = re.compile(r'^'
                              r'(\*|([0-5]?[0-9])([-/][0-5]?[0-9])*(,[0-5]?[0-9])*) '  # 分钟
                              r'(\*|([01]?[0-9]|2[0-3])([-/][01]?[0-9]|2[0-3])*(,[01]?[0-9]|2[0-3])*) '  # 小时
                              r'(\*|([1-2]?[0-9]|3[0-1])([-/][1-2]?[0-9]|3[0-1])*(,[1-2]?[0-9]|3[0-1])*) '  # 日期
                              r'(\*|(1[0-2]|[1-9])|(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)([-/](1[0-2]|[1-9])|(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC))*(,(1[0-2]|[1-9])|(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)*)*) '  # 月份
                              r'(\*|([0-7])([-/][0-7])*(,[0-7])*)$')  # 星期几
    if not cron_pattern.match(cron_cycle):
        raise ValueError("Invalid cron_cycle format. Expected format: * * * * *")
    if not host or not user or not script_task:
        raise ValueError("Host, User, or ScriptTask not found")
    content = script_task.content.replace('\r\n', '\n')
    # 创建临时文件并写入脚本内容
    with tempfile.NamedTemporaryFile(delete=False, mode='w',encoding='utf-8') as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    # 创建 SSH 连接
    conn = Connection(
        host=host.ip_address,
        user=user.username,
        connect_kwargs={"password": user.password}
    )
    # 上传脚本文件到远程主机
    remote_path = f"/tmp/{script_task.name}"
    conn.put(temp_file_path, remote=remote_path)
    conn.run(f"sed -i 's/\r$//' {remote_path}")
    output_log = f"{remote_path}.log"
    error_log = f"{remote_path}.err"
    # 设置定时任务
    cron_command = f"{cron_cycle} {remote_path} >> {output_log} 2>> {error_log}"  # 每分钟执行一次，可以根据需要调整
    conn.run(f"(crontab -l 2>/dev/null; echo '{cron_command}') | crontab -")
    updateLast_RunInfo(script_task_id)
    return f"Script scheduled with cron job: {cron_command}"


# try:
#     # 执行脚本并获取结果
#     result = conn.run(content, hide=True)
#
#     # 创建新的日志条目
#     new_log = ScriptLog(
#         script_task_id=script_task_id,
#         result=result.stdout+result.stderr,
#         host_info=f
#         status=result.success,
#         executor_role="Name:"+g.current_user["user_name"]+"Account:"+g.current_user["user_account"]

#     )
#     db.session.add(new_log)
#     db.session.commit()
#     updateLast_RunInfo(script_task_id)
#     return f"Script scheduled with cron job: {cron_command}"
# except Exception as e:
#     db.session.rollback()
#     raise e