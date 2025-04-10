from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from ..services.processMonitorService import *  # 假设服务函数在 processMonitorService 中
from app import db

process_monitor_bp = Blueprint('process_monitor_bp', __name__)

@process_monitor_bp.route('/api/log-monitor/pageQuery', methods=['GET'])
def get_log_monitor():
    try:
        # 获取分页参数，默认值为第一页，每页 10 条记录
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))

        # 获取查询参数
        hostname = request.args.get('hostname')
        process_name = request.args.get('process_name')
        process_status = request.args.get('process_status')
        is_suspended = request.args.get('is_suspended')

        # 构建查询对象
        query = db.query(LogMonitor)

        # 动态添加查询条件
        if hostname:
            query = query.filter(LogMonitor.hostname.ilike(f'%{hostname}%'))
        if process_name:
            query = query.filter(LogMonitor.process_name.ilike(f'%{process_name}%'))
        if process_status:
            query = query.filter(LogMonitor.process_status == process_status)
        if is_suspended:
            query = query.filter(LogMonitor.is_suspended == (is_suspended.lower() == 'true'))

        # 执行分页查询
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        # 构建响应数据
        logs = [log.to_dict() for log in pagination.items]
        response_data = {
            'items': logs,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': pagination.page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }

        return jsonify({
            "status": "success",
            "message": "Logs retrieved successfully",
            "data": response_data
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An error occurred while retrieving logs: {e}"
        }), 500


@process_monitor_bp.route('/api/log-monitor/<entry_id>', methods=['GET'])
def get_entry_by_id_route(entry_id):
    entry = get_entry_by_id(entry_id)
    if not entry:
        return jsonify({"status": "error", "message": "Entry not found"}), 404
    return jsonify({"status": "success", "data": entry}), 200


@process_monitor_bp.route('/api/log-monitor', methods=['POST'])
def create_entry_route():
    data = request.json
    new_entry = create_entry(data)
    return jsonify({"status": "success", "data": new_entry}), 201


@process_monitor_bp.route('/api/log-monitor/<entry_id>', methods=['PUT'])
def update_entry_route(entry_id):
    data = request.json
    updated_entry = update_entry(entry_id, data)
    if not updated_entry:
        return jsonify({"status": "error", "message": "Entry not found"}), 404
    return jsonify({"status": "success", "data": updated_entry}), 200


@process_monitor_bp.route('/api/log-monitor/<entry_id>', methods=['DELETE'])
def delete_entry_route(entry_id):
    success = delete_entry(entry_id)
    if not success:
        return jsonify({"status": "error", "message": "Entry not found"}), 404
    return jsonify({"status": "success", "message": "Entry deleted successfully"}), 200


@process_monitor_bp.route('/api/log-monitor/<entry_id>/suspend', methods=['POST'])
def suspend_entry_route(entry_id):
    suspend_duration = int(request.json.get("duration", 3600))  # 默认挂起 1 小时
    suspend_until = datetime.now() + timedelta(seconds=suspend_duration)
    suspended_entry = suspend_entry(entry_id, suspend_until)
    if not suspended_entry:
        return jsonify({"status": "error", "message": "Entry not found"}), 404
    return jsonify({"status": "success", "data": suspended_entry}), 200
