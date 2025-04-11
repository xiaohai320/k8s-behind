from flask import Blueprint, request, jsonify
from ..services.diskMonitorService import *
from ..commonutils.R import R  # 确保 R 类已导入
from ..utils.auth import token_required
from ..utils.check_permission import permission_required
disk_monitor_bp = Blueprint('disk_monitor_bp', __name__)

# 接收磁盘监控数据
@disk_monitor_bp.route('/api/disk-monitor', methods=['POST'])
def receive_disk_data():
    data = request.json
    if not data:
        return R.error().set_message("No data provided").to_json()

    save_disk_data(data)
    return R.ok().set_message("Data saved successfully").to_json()

# 查询磁盘监控数据
@disk_monitor_bp.route('/api/disk-monitor', methods=['GET'])
@token_required
@permission_required("admin")
def query_disk_data():
    hostname = request.args.get('hostname', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    result = get_disk_data(hostname=hostname, page=page, per_page=per_page)
    return R.ok().set_message("Data retrieved successfully").set_data({
        "items": [item.to_dict() for item in result['data']],
        "total": result['total']
    }).to_json()
# 修改磁盘监控告警阈值
@disk_monitor_bp.route('/api/disk-monitor', methods=['PUT'])
def update_alert_threshold():
    data = request.json
    if not data or 'hostname' not in data or 'disk_path' not in data or 'alert_threshold' not in data:
        return jsonify({"message": "Invalid data provided"}), 400

    hostname = data['hostname']
    disk_path = data['disk_path']
    alert_threshold = data['alert_threshold']

    # 调用服务方法更新告警阈值
    success = update_disk_alert_threshold(hostname, disk_path, alert_threshold)
    if success:
        return R.ok().set_message(f"Alert threshold updated for host {hostname} and disk path {disk_path}").to_json()
    else:
        return R.error().set_message(f"No records found for host {hostname} and disk path {disk_path}").to_json()