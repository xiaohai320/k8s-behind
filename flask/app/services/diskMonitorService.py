from ..models.diskMonitorModel import  DiskMonitor
from sqlalchemy import desc
from app import db

def save_disk_data(data):
    """
    保存磁盘监控数据到数据库
    :param data: List[Dict] - 磁盘监控数据列表
    """
    for record in data:
        # 提取空间数据和单位
        total_space_value, total_space_unit = extract_space_value_and_unit(record['total_space'])
        used_space_value, used_space_unit = extract_space_value_and_unit(record['used_space'])
        free_space_value, free_space_unit = extract_space_value_and_unit(record['free_space'])

        # 转换所有空间数据为 GB
        total_space_gb = convert_to_gb(total_space_value, total_space_unit)
        used_space_gb = convert_to_gb(used_space_value, used_space_unit)
        free_space_gb = convert_to_gb(free_space_value, free_space_unit)

        # 计算 percent_used
        if total_space_gb == 0:
            percent_used = 0
        else:
            percent_used = (used_space_gb / total_space_gb) * 100

        # 计算 is_alert
        alert_threshold_gb = convert_to_gb(1000, 'GB')
        # is_alert = 1 if free_space_gb < alert_threshold_gb else 0

        # 查询是否存在相同的记录
        existing_record = DiskMonitor.query.filter_by(
            hostname=record['hostname'],
            disk_path=record['disk_path']
        ).first()

        if existing_record:
            # 更新现有记录
            existing_record.total_space = f"{total_space_gb:.3f}GB"
            existing_record.used_space = f"{used_space_gb:.3f}GB"
            existing_record.free_space = f"{free_space_gb:.3f}GB"
            existing_record.percent_used = f"{percent_used:.2f}"
            existing_record.alert_threshold = alert_threshold_gb
            # existing_record.is_alert = is_alert
            # existing_record.update_time = record['update_time']
        else:
            # 插入新记录
            disk_record = DiskMonitor(
                hostname=record['hostname'],
                disk_path=record['disk_path'],
                total_space=f"{total_space_gb:.3f}GB",
                used_space=f"{used_space_gb:.3f}GB",
                free_space=f"{free_space_gb:.3f}GB",
                percent_used= f"{percent_used:.2f}",
                alert_threshold=alert_threshold_gb,
                # is_alert=is_alert,
                # update_time=record['update_time']11
            )
            db.session.add(disk_record)

    db.session.commit()



import re

def extract_space_value_and_unit(space_str):
    # 修改正则表达式以支持小数
    match = re.match(r"^(\d+(\.\d+)?)([A-Za-z]+)$", space_str)
    if match:
        value = float(match.group(1))
        unit = match.group(3).upper()  # 将单位转换为大写，便于统一处理
        if unit == 'M':  # 将 M 视为 MB
            unit = 'MB'
        elif unit == 'G':  # 将 G 视为 GB
            unit = 'GB'
        return value, unit
    else:
        raise ValueError(f"Invalid space string format: {space_str}")

def convert_to_gb(value, unit):
    """
    将空间值转换为 GB
    :param value: float - 空间值
    :param unit: str - 单位，例如 "GB" 或 "MB"
    :return: float - 转换后的 GB 值
    """
    if unit == 'GB':
        return value
    elif unit == 'MB':
        return value / 1024
    else:
        raise ValueError(f"Unsupported unit for conversion: {unit}")


def update_disk_alert_threshold(hostname, disk_path, alert_threshold):
    """
    更新磁盘监控数据中的告警阈值
    :param hostname: str - 主机名
    :param disk_path: str - 磁盘路径
    :param alert_threshold: float - 新的告警阈值
    :return: bool - 是否成功更新
    """
    # 查询符合条件的记录
    record = DiskMonitor.query.filter_by(hostname=hostname, disk_path=disk_path).first()
    if not record:
        return False

    # 更新记录的告警阈值
    record.alert_threshold = alert_threshold

    # 提交更改到数据库
    db.session.commit()
    return True

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

    # 调试：打印所有唯一主机名
    hostnames = query.with_entities(DiskMonitor.hostname).distinct().all()
    print("Distinct hostnames:", [hostname[0] for hostname in hostnames])

    # 统计唯一主机名数量
    total = query.count()

    # 分页查询数据
    data = query.order_by(desc(DiskMonitor.update_time)).paginate(page=page, per_page=per_page, error_out=False).items

    return {"data": data, "total": total}