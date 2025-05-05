from flask import Blueprint, request

from ..commonutils.R import R
from ..services.sshServices import *
from ..utils.auth import token_required
from ..utils.check_permission import permission_required
from ..utils.operation_record import operation_record

ssh_bp = Blueprint('sshInfo', __name__)


# Host routes
@ssh_bp.route('/linux_all_hosts', methods=['GET'])
@token_required
@permission_required('list_linux_hosts')

def list_all_hosts_view():
    try:
        hosts = list_all_hosts()
        return R.ok().set_data([host.to_dict() for host in hosts]).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts/<int:page>/<int:per_page>', methods=['GET'])
@token_required
@permission_required('list_linux_hosts')

def list_hosts_view(page, per_page):
    try:
        querySearch = request.args.get('querySearch')
        hosts = list_hosts(page, per_page, querySearch)
        return R.ok().set_data(hosts).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts/<int:host_id>', methods=['GET'])
@token_required
@permission_required('list_linux_hosts')
def get_host_view(host_id):
    try:
        host = get_host(host_id)
        if not host:
            return R.error().set_message("Host not found").to_json()
        return R.ok().set_data(host.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts', methods=['POST'])
@operation_record(description='创建linux主机')
@token_required
@permission_required('create_linux_host')
def create_host_view():
    try:
        data = request.json
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        port= data.get('port')
        description = data.get('description')
        if not hostname or not ip_address:
            return R.error().set_message("Hostname and IP address are required").to_json()
        new_host = create_host(hostname, ip_address,port,description)
        return R.ok().set_data(new_host.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts/<string:host_ip>/root_credentials', methods=['GET'])
@token_required
# @permission_required('get_root_credentials')
def get_root_credentials_view(host_ip):
    try:
        # 获取主机信息
        print(host_ip)
        host = get_host_by_ip(host_ip)
        if not host:
            return R.error().set_message("Host not found").to_json()

        # 获取 root 用户信息
        root_user = get_root_user_by_host(host.id)
        if not root_user:
            return R.error().set_message("Root user not found for this host").to_json()
        # 返回 root 用户的账户密码
        # 注意：在实际应用中，不应该直接返回密码，可以考虑返回加密后的密码或者密钥
        return R.ok().set_data({
            'username': root_user.username,
            'password': root_user.password  # 注意：这里直接返回密码仅用于示例，实际应用中请谨慎处理
        }).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts/chooseRole/<string:host_ip>', methods=['GET'])
# @token_required
# @permission_required('list_linux_hosts')
def get_role_credentials_view(host_ip):
    try:
        # 获取主机信息
        host = get_host_by_ip(host_ip)
        if not host:
            return R.error().set_message("Host not found").to_json()

        # 获取该主机的所有用户信息
        users = get_users_by_host(host.id)
        if not users:
            return R.error().set_message("No users found for this host").to_json()

        # 返回用户信息
        # 注意：在实际应用中，不应该直接返回密码，可以考虑返回加密后的密码或者密钥
        user_info_list = [
            {
                'username': user.username,
                'password': user.password  # 注意：这里直接返回密码仅用于示例，实际应用中请谨慎处理
            }
            for user in users
        ]
        return R.ok().set_data(user_info_list).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_hosts/<int:host_id>', methods=['PUT'])
@token_required
@operation_record(description='修改linux主机')
@permission_required('update_linux_host')
def update_host_view(host_id):
    try:
        data = request.json
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        port= data.get('port')
        description = data.get('description')
        updated_host = update_host(host_id, hostname, ip_address, port, description)
        if not updated_host:
            return R.error().set_message("Host not found").to_json()
        return R.ok().set_data(updated_host.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()



@ssh_bp.route('/linux_hosts/<int:host_id>', methods=['DELETE'])
@token_required
@operation_record(description='删除linux主机')
@permission_required('delete_linux_host')
def delete_host_view(host_id):
    try:
        deleted_host = delete_host(host_id)
        if not deleted_host:
            return R.error().set_message("Host not found").to_json()
        return R.ok().set_message("Host deleted successfully").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

# User routes
@ssh_bp.route('/linux_users', methods=['GET'])
@token_required
@permission_required('list_linux_users')
def list_users_view():
    try:
        users = list_users()
        return R.ok().set_data([user.to_dict() for user in users]).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_users/host/<int:host_id>', methods=['GET'])
@token_required
@permission_required('list_linux_users')

def get_users_by_host_view(host_id):
    try:
        users = get_users_by_host(host_id)
        if not users:
            return R.info().set_message("No users found for this host").to_json()
        return R.ok().set_data([user.to_dict() for user in users]).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()


@ssh_bp.route('/linux_users/<int:user_id>', methods=['GET'])
@token_required
@permission_required('list_linux_users')

def get_user_view(user_id):
    try:
        user = get_user(user_id)
        if not user:
            return R.info().set_message("User not found").to_json()
        return R.ok().set_data(user.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_users', methods=['POST'])
@token_required
@operation_record(description='创建linux用户')
@permission_required('create_linux_user')
def create_user_view():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        host_id = data.get('host_id')
        if not username or not password or not host_id:
            return R.info().set_message("Username, password, and host_id are required").to_json()
        new_user = create_user(username, password, host_id)
        return R.ok().set_data(new_user.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_users/<int:user_id>', methods=['PUT'])
@token_required
@operation_record(description='修改linux用户')
@permission_required('update_linux_user')
def update_user_view(user_id):
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        host_id = data.get('host_id')
        updated_user = update_user(user_id, username, password, host_id)
        if not updated_user:
            return R.info().set_message("User not found").to_json()
        return R.ok().set_data(updated_user.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/linux_users/<int:user_id>', methods=['DELETE'])
@token_required
@permission_required('delete_linux_user')
@operation_record(description='删除linux用户')
def delete_user_view(user_id):
    try:
        deleted_user = delete_user(user_id)
        if not deleted_user:
            return R.info().set_message("User not found").to_json()
        return R.ok().set_message("User deleted successfully").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/script-tasks', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='创建脚本任务')
@permission_required('create_script_task')
def create_script_task_view():
    data = request.json
    if not all(k in data for k in ('name', 'content', 'author')):
        return R.error().set_message("Missing required fields").to_json()
    content = data['content'].replace('\r\n', '\n')
    try:
        task = create_script_task(
            name=data['name'],
            content=content,
            author=data['author']
        )
        return R.ok().set_message("Script task created").set_data(task.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/script-tasks/<int:task_id>', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
@permission_required('get_script_task')
def get_script_task_view(task_id):
    try:
        task = get_script_task(task_id)
        if not task:
            return R.info().set_message("Script task not found").to_json(), 404
        return R.ok().set_data(task.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/hosts/common_users', methods=['POST'])
@token_required
@permission_required('get_common_users')
def get_common_users():
    data = request.get_json()
    host_ids = data.get('host_ids', [])
    if not host_ids:
        return R.error().set_message('No host IDs provided').to_json()
    # 查询所有主机
    hosts = LinuxHost.query.filter(LinuxHost.id.in_(host_ids)).all()
    if not hosts:
        return R.error().set_message('No hosts found with the provided IDs').to_json()
    # 获取每个主机的用户集合
    # user_sets = [set(host.users) for host in hosts]
    user_sets = []
    for host in hosts:
        users_info = [{'id': user.id, 'username': user.username,'host_id':user.host_id} for user in host.users]
        user_sets.append(users_info)
    user_name_sets = [{user['username'] for user in users} for users in user_sets]
    print(f"User names sets: {user_name_sets}")
    # 计算所有主机的共有用户名
    if user_name_sets:
        common_usernames = set.intersection(*user_name_sets)
    else:
        common_usernames = set()
    common_users = []
    for username in common_usernames:
        for users in user_sets:
            for user in users:
                if user['username'] == username and (not host_ids or user['host_id'] in host_ids):
                    common_users.append(user)
                    break  # 每个用户名只添加一次

  # 返回共有的用户
    return R.ok().set_message("Success Get CommonUsers").set_data(common_users).to_json()

@ssh_bp.route('/script-logs/<int:log_id>', methods=['DELETE'])
@token_required
@operation_record(description='删除日志')
@permission_required('delete_script_log')
def delete_script_log(log_id):
    try:
        log = delete_log(log_id)
        if not log:
            return R.info().set_message("Log not found").to_json()
        return R.ok().set_message("Log deleted successfully").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/script-logs/pageQuery/<int:page>/<int:per_page>', methods=['GET'])
@token_required
@permission_required('get_script_log')
def get_logs_with_pagination_view(page, per_page):
    try:
        script_name = request.args.get('script_name')
        host_info = request.args.get('host_info')
        executor_role = request.args.get('executor_role')
        status = request.args.get('status')
        response_data = get_logs_with_pagination(page, per_page, script_name, host_info, executor_role, status)
        return R.ok().set_message('Logs retrieved successfully').set_data(response_data).to_json()
    except Exception as e:
        return R.error().set_message(f'An error occurred while retrieving logs: {e}').to_json()
@ssh_bp.route('/script-tasks/<int:page>/<int:per_page>', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
# @operation_record(description='获取脚本任务')
@permission_required('get_script_task')
def list_script_tasks_view( page, per_page):
    try:
        script_name = request.args.get('script_name')
        response_data = list_script_tasks(page, per_page, script_name)
        return R.ok().set_data(response_data).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/script-all-tasks', methods=['GET'])
@token_required
@permission_required('get_script_task')
def list_all_script_tasks_view():
    try:
        tasks = list_all_script_tasks()
        return R.ok().set_data([task.to_dict() for task in tasks]).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()
@ssh_bp.route('/script-tasks/<int:task_id>', methods=['PUT'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='更新脚本任务')
@permission_required('update_script_task')
def update_script_task_view(task_id):
    data = request.json
    if not data:
        return R.error().set_message("No data provided").to_json()
    try:
        task = update_script_task(
            task_id=task_id,
            name=data.get('name'),
            content=data.get('content'),
        )
        if not task:
            return R.error().set_message("Script task not found").to_json()
        return R.ok().set_message("Script task updated").set_data(task.to_dict()).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/script-tasks/<int:task_id>', methods=['DELETE'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='删除脚本任务')
@permission_required('delete_script_task')
def delete_script_task_view(task_id):
    try:
        success = delete_script_task(task_id)
        if not success:
            return R.info().set_message("Script task not found").to_json()
        return R.ok().set_message("Script task deleted").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@ssh_bp.route('/execute_script_once', methods=['POST'])
@token_required
@permission_required('execute_script')
@operation_record(description='执行一次脚本')
def execute_script_once_view():
    try:
        data = request.json
        host_id = data.get('host_id')
        user_id = data.get('user_id')
        script_task_id = data.get('script_task_id')
        if not host_id or not user_id or not script_task_id:
            return R.error().set_message("host_id, user_id, and script_task_id are required").to_json()
        result = execute_script_once(host_id, user_id, script_task_id)

        return R.ok().set_message("Success").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()
@ssh_bp.route('/schedule_script', methods=['POST'])
@token_required
@permission_required('execute_script')
@operation_record(description='定时执行脚本')
def schedule_script_view():
    try:
        data = request.json
        host_id = data.get('host_id')
        user_id = data.get('user_id')
        script_task_id = data.get('script_task_id')
        cron_cycle = data.get('cron_cycle')
        working_directory = data.get('working_directory')
        if not host_id or not user_id or not script_task_id:
            return R.error().set_message("host_id, user_id, and script_task_id are required").to_json()
        result = cron_script(host_id, user_id, script_task_id, cron_cycle, working_directory)
        return R.ok().set_data(result).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()
