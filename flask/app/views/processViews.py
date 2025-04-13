from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from ..services.processMonitorService import *  # 假设服务函数在 processMonitorService 中
from ..commonutils.R import R  # 确保 R 类已导入
from ..utils.auth import token_required
from ..utils.check_permission import permission_required
from ..utils.operation_record import operation_record

process_monitor_bp = Blueprint('process_monitor_bp', __name__)

@process_monitor_bp.route('/api/log-monitor/pageQuery', methods=['GET'])
@token_required
@permission_required('admin')
@operation_record(description='获取日志监控列表')
def get_log_monitor():
    try:
        # 获取分页参数，默认值为第一页，每页 10 条记录
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        # 获取查询参数
        hostname = request.args.get('hostname')
        process_name = request.args.get('process_name')
        process_status = request.args.get('process_status')
        # 构建查询对象
        query = db.session.query(LogMonitor)
        # 动态添加查询条件
        if hostname:
            query = query.filter(LogMonitor.hostname.ilike(f'%{hostname}%'))
        if process_name:
            query = query.filter(LogMonitor.process_name.ilike(f'%{process_name}%'))
        if process_status:
            query = query.filter(LogMonitor.process_status == process_status)
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

        return R.ok().set_message('Logs retrieved successfully').set_data(response_data).to_json()

    except Exception as e:
        return R.error().set_message(f"An error occurred while retrieving logs: {e}").to_json()

@process_monitor_bp.route('/api/log-monitor/<entry_id>', methods=['GET'])
@token_required
@permission_required('admin')
@operation_record(description='获取日志监控详情')
def get_entry_by_id_route(entry_id):
    entry = get_entry_by_id(entry_id)
    if not entry:
        return R.error().set_message("Entry not found").to_json()
    return R.ok().set_message('Entry retrieved successfully').set_data(entry).to_json()

@process_monitor_bp.route('/api/log-monitor', methods=['POST'])

def create_entry_route():
    data = request.json
    print(data)
    new_entry = create_entry(data)
    return R.ok().set_message('Entry created successfully').set_data(new_entry).to_json()


@process_monitor_bp.route('/read_log', methods=['POST'])
@token_required
@permission_required('admin')
@operation_record(description='读取日志')
def read_log():
    try:
        data = request.get_json()
        hostname = data.get('hostname')
        script_name = data.get('script_name')
        log_path = data.get('log_path')
        log_type=data.get('log_type')
        if not hostname or not script_name or not log_path or not log_type:
            return R.error().set_message('Missing required fields').to_json()
        log_content = read_log_from_host(hostname, script_name, log_path,log_type)

        if log_content:
            return R.ok().set_message('Log retrieved successfully').set_data({'log_content': log_content}).to_json()
        else:
            return R.error().set_message('Failed to retrieve log').to_json()
    except Exception as e:
        current_app.logger.error(f"Error in read_log endpoint: {e}")
        return R.error().set_message(f"Error in read_log endpoint: {e}").to_json()

