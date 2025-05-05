
import requests
from flask import Blueprint, request, abort
from requests.exceptions import RequestException

from ..services.kubeServices import *
from ..utils.auth import token_required
from ..utils.check_permission import permission_required
from ..utils.operation_record import operation_record

alert_bp = Blueprint('alert', __name__)
k8s_bp = Blueprint('k8s', __name__)
deploy_bp = Blueprint('deploy', __name__)
@alert_bp.route('/getalertinfo', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def get_alert_info():
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('pageSize', 10))
        # 获取查询参数
        status = request.args.get('status')  # 可选：挂起/激活等状态
        severity = request.args.get('severity')  # 可选：Pod名称或其他标识符
        query = AlertsInfo.query
        # 根据查询参数构建过滤条件
        if status and status.strip():
            if status=='firing' or status== 'resolved':
             query = query.filter(AlertsInfo.status == status)
             query = query.filter(AlertsInfo.suspend_status != 'suspended')
            elif status=='suspended':
                query = query.filter(AlertsInfo.suspend_status == "suspended")
            elif status=='unsuspended':
                query = query.filter(AlertsInfo.suspend_status == "unsuspended")
        else:
            query = query.filter(AlertsInfo.suspend_status != 'suspended')
        if severity and severity.strip():
            query = query.filter(AlertsInfo.severity==severity)
        # 应用分页
        query = query.order_by(AlertsInfo.updated_at.desc())
        paginated_alerts = query.paginate(page=page, per_page=page_size, error_out=False)
        # print(paginated_alerts.items)
        total = paginated_alerts.total
        alerts = [alert.to_dict() for alert in paginated_alerts.items]
        return R.ok().set_data({
            'total': total,
            'alerts': alerts,
            'currentPage': page
        }).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@alert_bp.route('/postalertinfo', methods=['POST'])

def post_alert_info():
    try:
        data = request.json
        if not data:
            return R.error().set_message('No data provided').to_json()
        alerts = data.get('alerts', [])
        for alert in alerts:
            status = alert.get('status', 'unknown')
            fingerprint = alert.get('fingerprint')
            print(alert['labels'].get('log', ''))
            if status == 'firing':
                insert_or_update_alert(alert)
            elif status == 'resolved':
                delete_alert(fingerprint)
        return R.ok().set_message('Alert received and saved').to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@alert_bp.route('/getalertmanagerrule', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def get_alertmanager_rule():
    try:
        response = requests.get(f'{current_app.config["ALERTMANAGER_URL"]}/alerts')
        response.raise_for_status()  # 检查请求是否成功
        alerts = response.json()
        return R.ok().set_data(alerts).to_json()
    except RequestException as e:
        return R.error().set_message(str(e)).to_json()
@k8s_bp.route('/pods', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def list_pods_info():
    podName = request.args.get('podName', '')
    page = int(request.args.get('page', 1))
    pageSize = int(request.args.get('pageSize', 10))
    try:
        # 调用服务层的函数来获取 Pod 列表和总数
        pods_data = list_pods(podName if podName else None, page, pageSize)
        return R.ok().set_data(pods_data).to_json()

    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@k8s_bp.route('/operations', methods=['GET'])
def get_operations_view():
    try:
        operations = get_operations()
        return R.ok().set_data(operations).to_json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@k8s_bp.route('/delete_pod', methods=['DELETE'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='删除Pod')
def delete_pod():
    namespace = request.args.get('namespace')
    pod_name = request.args.get('pod_name')
    try:
        # 调用服务层的函数来删除指定的 Pod
        result = service_delete_pod(namespace, pod_name)

        if result:
            return R.ok().set_message(f"Pod '{pod_name}' in namespace '{namespace}' deleted successfully.").to_json()
        else:
            return R.error().set_message(f"Failed to delete Pod '{pod_name}' in namespace '{namespace}'.").to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()

@k8s_bp.route('/scale-pods', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='扩缩容Pod')
def scale_pods():
    data = request.json
    if not all(k in data for k in ('namespace','controller_name', 'replicas','type')):
        return R.error().set_message("缺少必要参数!").to_json()
    try:
        if data['type']=='deployment':
            response = scale_deployment(data['controller_name'], data.get('namespace'), data['replicas'])
        elif data['type']=='statefulset':
            response = scale_statefulset(data['controller_name'], data.get('namespace'), data['replicas'])
        else:
            return R.error().set_message("type参数错误!").to_json()
        if not response:
            return R.error().set_message("修改副本数失败").to_json()
        return R.ok().set_message(f"Deployment '{data['controller_name']}' scaled to {data['replicas']} replicas").to_json()
    except (ApiException, ValueError) as e:
        return R.error().set_message(str(e)).to_json()
@k8s_bp.route('/deployments/<string:namespace>/<string:deployment_name>', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def get_deployment(namespace, deployment_name):
    try:
        deployment = get_deployment_details(deployment_name, namespace)
        return R.ok().set_data(deployment.to_dict()).to_json()
    except ApiException as e:
        if e.status == 404:
            abort(404, description="Deployment not found")
        else:
            abort(500, description=str(e))
    except Exception as e:
        abort(500, description=str(e))

@k8s_bp.route('/nodes', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def list_nodes_view():
    name = request.args.get('nodeName')
    try:

        nodes = list_nodes(name)

        if not nodes:
            return R.error().set_message("No nodes found").to_json()
        else:
            return R.ok().set_data(nodes.to_dict()).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()


@k8s_bp.route('/svc', methods=['GET'])
# @token_required  # 如果需要认证，则添加此装饰器
def list_svc():
    namespace = request.args.get('namespace',"default")
    label = request.args.get('label', '')
    try:
        svc = list_services(namespace, label)
        return R.ok().set_data([service.to_dict() for service in svc.items]).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()

@k8s_bp.route('/namespaces', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def list_namespaces_view():
    try:
        namespaces = list_namespaces()
        return R.ok().set_data([ns.metadata.name for ns in namespaces.items]).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()

@k8s_bp.route('/controllers', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def list_controllers_view():
    namespace = request.args.get('namespace', 'default')
    controller_name = request.args.get('podcontrollername')
    controller_type = request.args.get('podcontrollertype')
    try:
        controllers = list_controllers(namespace, controller_name, controller_type)
        return R.ok().set_data(controllers).to_json()
    except (ApiException, ValueError) as e:
        return R.error().set_message(str(e)).to_json()

@deploy_bp.route('/deployments', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
def create_deployment():
    data = request.json
    if not all(k in data for k in ('namespace', 'name', 'image')):
        return R.error().set_message("Missing required fields").to_json()

    try:
        dep_obj = create_deployment_object(data['namespace'], data['name'], data['image'])
        response = apps_v1.create_namespaced_deployment(data['namespace'], dep_obj)
        return R.ok().set_message("Deployment created").set_data(response.to_dict()).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()


@deploy_bp.route('/deployments', methods=['GET'])
@token_required  # 如果需要认证，则添加此装饰器
def list_deployments():
    namespace = request.args.get('namespace', 'default')
    try:
        deploys = apps_v1.list_namespaced_deployment(namespace)
        return R.ok().set_data([deploy.to_dict() for deploy in deploys.items]).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()


@deploy_bp.route('/deployments/<string:namespace>/<string:name>', methods=['PUT'])
@token_required  # 如果需要认证，则添加此装饰器
def update_deployment(namespace, name):
    data = request.json
    if 'image' not in data:
        return R.error().set_message("Missing required fields").to_json()

    try:
        deployment = apps_v1.read_namespaced_deployment(name, namespace)
        deployment.spec.template.spec.containers[0].image = data['image']
        response = apps_v1.patch_namespaced_deployment(name, namespace, deployment)
        return R.ok().set_message("Deployment updated").set_data(response.to_dict()).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()

@deploy_bp.route('/deployments/<string:namespace>/<string:name>', methods=['DELETE'])
@token_required  # 如果需要认证，则添加此装饰器
def delete_deployment(namespace, name):
    try:
        response = apps_v1.delete_namespaced_deployment(
            name,
            namespace,
            body=client.V1DeleteOptions(
                propagation_policy='Foreground',
                grace_period_seconds=5
            )
        )
        return R.ok().set_message("Deployment deleted").set_data(response.to_dict()).to_json()
    except ApiException as e:
        return R.error().set_message(str(e)).to_json()


@alert_bp.route('/addrules', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
def add_alert_rules():
    data = request.json
    return update_configmap(data)

@alert_bp.route('/deleterules', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
def delete_alert_rules():
    alert_name = request.json.get('alert_name')
    if not alert_name:
        return R.error().set_message("alert_name is required").to_json(), 400
    return delete_alert_rule(alert_name)

@alert_bp.route('/modifyrules', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
def modify_alert_rules():
    data = request.json
    namespace = data.get('namespace')
    configmap_name = data.get('configmap_name')
    alert_name = data.get('alert_name')
    new_rule = data.get('new_rule')

    if not all([namespace, configmap_name, alert_name, new_rule]):
        return R.error().set_message("Missing required parameters").to_json()
    return modify_alert_rule(namespace, configmap_name, alert_name, new_rule)
@alert_bp.route('/batch-suspend', methods=['POST'])
@token_required  # 如果需要认证，则添加此装饰器
@operation_record(description='批量挂起告警')
@permission_required('alert_suspend')
def suspend_alerts():
    data = request.get_json()
    ids = data.get('ids')
    suspend_until = data.get('suspend_until')
    reason = data.get('reason')
    try:
        # 调用服务层方法执行业务逻辑
        batch_suspend_alerts(ids, suspend_until, reason)
        db.session.commit()
        for alert_id in ids:
            schedule_unsuspend(alert_id, suspend_until)
        return R.ok().to_json()
    except Exception as e:
        db.session.rollback()
        return  R.error().set_message(str(e)).to_json()