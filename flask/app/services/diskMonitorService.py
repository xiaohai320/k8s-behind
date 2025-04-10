from ..models.diskMonitorModel import  DiskMonitor
from sqlalchemy import desc
from app import db

def save_disk_data(data):
    """
    保存磁盘监控数据到数据库
    :param data: List[Dict] - 磁盘监控数据列表
    """
    for record in data:
        disk_record = DiskMonitor(
            hostname=record['hostname'],
            disk_path=record['disk_path'],
            total_space=record['total_space'],
            used_space=record['used_space'],
            free_space=record['free_space'],
            percent_used=record['percent_used'],
            alert_threshold=record['alert_threshold'],
            is_alert=record['is_alert'],
            update_time=record['update_time']
        )
        db.session.add(disk_record)
    db.session.commit()


def get_disk_data(hostname='', page=1, per_page=10):
    """
    查询磁盘监控数据
    :param hostname: str - 主机名（可选）
    :param page: int - 当前页码
    :param per_page: int - 每页记录数
    :return: Dict - 查询结果
    """
    query = DiskMonitor.query
    if hostname:
        query = query.filter(DiskMonitor.hostname == hostname)
    total = query.count()
    data = query.order_by(desc(DiskMonitor.update_time)).paginate(page=page, per_page=per_page, error_out=False).items

    return {"data": data, "total": total}