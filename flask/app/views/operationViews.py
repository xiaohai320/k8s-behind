from datetime import datetime
from io import BytesIO
from zoneinfo import ZoneInfo

import openpyxl
from flask import Blueprint, current_app, request, send_file

from app.commonutils.R import R
from app.models.useroperationlog import UserOperationLog
from app.utils.auth import token_required
from app.utils.check_permission import permission_required

# 创建蓝图
operation_bp = Blueprint('operation_bp', __name__)
@operation_bp.route('/pageQueryOperationLogs/<int:page>/<int:per_page>', methods=['GET'])
@token_required
@permission_required('query_operation_log')
def page_query_operation_logs(page, per_page):
    try:
        # 获取查询参数
        user_account = request.args.get('user_account')  # 用户账号
        operation = request.args.get('operation')        # 操作描述
        start_time = request.args.get('beginTime')      # 开始时间
        end_time = request.args.get('endTime')          # 结束时间

        # 构建查询对象
        query = UserOperationLog.query

        # 动态添加查询条件
        if user_account:
            query = query.filter(UserOperationLog.user_account.ilike(f'%{user_account}%'))
        if operation:
            query = query.filter(UserOperationLog.operation.ilike(f'%{operation}%'))
        if start_time and end_time:
            # 将UTC时间转换为Asia/Shanghai时间
            start_time_converted = datetime.fromisoformat(start_time).astimezone(ZoneInfo('Asia/Shanghai'))
            end_time_converted = datetime.fromisoformat(end_time).astimezone(ZoneInfo('Asia/Shanghai'))

            query = query.filter(UserOperationLog.timestamp.between(start_time_converted, end_time_converted))
        # 执行分页查询

        pagination = query.order_by(UserOperationLog.timestamp.desc()).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

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
        return R.ok().set_message('Operation logs retrieved successfully').set_data(response_data).to_json()

    except Exception as e:
        current_app.logger.error(f"Error retrieving operation logs: {e}")
        return R.error().set_message(f'An error occurred while retrieving operation logs: {e}').to_json()



@operation_bp.route('/export-operation-logs', methods=['POST'])
@token_required
@permission_required('query_operation_log')
def export_operation_logs():
    try:
        # 获取请求参数
        data = request.json
        begin_time = data.get('beginTime')
        end_time = data.get('endTime')

        user_account = data.get('user_account')
        # 构建查询对象
        query = UserOperationLog.query

        # 动态添加查询条件
        if begin_time and end_time:
            # 将UTC时间转换为Asia/Shanghai时间
            start_time_converted = datetime.fromisoformat(begin_time).astimezone(ZoneInfo('Asia/Shanghai'))
            end_time_converted = datetime.fromisoformat(end_time).astimezone(ZoneInfo('Asia/Shanghai'))
            query = query.filter(UserOperationLog.timestamp.between(start_time_converted, end_time_converted))

        if user_account and user_account.strip():
            query = query.filter(UserOperationLog.user_account.ilike(f'%{user_account}%'))

        # 执行查询
        logs = query.all()

        # 创建 Excel 文件
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "操作日志"
        # 写入表头
        headers = ["用户账号", "操作描述", "操作详情", "操作时间"]
        sheet.append(headers)
        # 写入数据
        for log in logs:
            row = [
                log.user_account,
                log.operation,
                str(log.details),
                log.timestamp
            ]
            sheet.append(row)

        # 将 Excel 文件保存到内存中
        output = BytesIO()
        workbook.save(output)
        output.seek(0)
        # 返回文件流
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name="operation_logs.xlsx"
        )
    except Exception as e:
        # 捕获异常并返回错误信息
        return R.error().set_message(str(e)).to_json()

