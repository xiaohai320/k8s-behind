from flask import Blueprint, request, jsonify
from ..services.diskMonitorService import *


disk_monitor_bp = Blueprint('disk_monitor_bp', __name__)

# 接收磁盘监控数据
@disk_monitor_bp.route('/api/disk-monitor', methods=['POST'])
def receive_disk_data():
    data = request.json
    if not data:
        return jsonify({"message": "No data provided"}), 400

    save_disk_data(data)
    return jsonify({"message": "Data saved successfully"}), 200

# 查询磁盘监控数据
@disk_monitor_bp.route('/api/disk-monitor', methods=['GET'])
def query_disk_data():
    hostname = request.args.get('hostname', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))

    result = get_disk_data(hostname=hostname, page=page, per_page=per_page)
    return jsonify({
        "data": [item.to_dict() for item in result['data']],
        "total": result['total']
    }), 200