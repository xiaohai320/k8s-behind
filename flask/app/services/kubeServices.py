
import subprocess
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import yaml
from apscheduler.triggers.date import DateTrigger
from dateutil import parser
from flask import jsonify, current_app
from kubernetes import client
from kubernetes.client.rest import ApiException
from sqlalchemy.exc import SQLAlchemyError

from app import core_v1, apps_v1, db, scheduler
from app.models.alertinfoModel import AlertsInfo
from ..commonutils.R import R  # 假设这是你的自定义响应类
from ..models.useroperationlog import UserOperationLog


def list_namespaced_pods(namespace='default'):
    """列出命名空间中的 Pods"""
    return core_v1.list_namespaced_pod(namespace)
def scale_deployment(deployment_name, namespace, replicas):
    """扩缩容 Deployment 的副本数"""
    try:
        deployment = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        deployment.spec.replicas = int(replicas)
        return apps_v1.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=deployment)
    except ApiException as e:
        print(f"Error scaling Deployment: {e}")
        return False
def scale_statefulset(statefulset_name,namespace, replicas):
    try:
        statefulset = apps_v1.read_namespaced_stateful_set(name=statefulset_name, namespace=namespace)
        statefulset.spec.replicas = int(replicas)
        return apps_v1.patch_namespaced_stateful_set(name=statefulset_name, namespace=namespace, body=statefulset)
    except ApiException as e:
        print(f"Error scaling StatefulSet: {e}")
        return False
def get_deployment_details(deployment_name, namespace='default'):
    """获取指定 Deployment 的详情"""
    return apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)

def list_nodes(node_name=None):
    """列出所有节点或指定节点的信息"""
    try:
        if node_name:
         return core_v1.read_node(node_name)
        else:
         return core_v1.list_node()
    except ApiException as e:
        print(f"Error deleting pod: {e}")
        return False
def list_services(namespace='default', label_selector=''):
    label_selector="app"+"="+label_selector
    """列出命名空间中的服务"""
    return core_v1.list_namespaced_service(namespace, label_selector=label_selector)

def service_delete_pod(namespace, pod_name):
    """删除指定服务关联的 Pod"""
    try:
        status=core_v1.delete_namespaced_pod(pod_name, namespace)
        return True
    except ApiException as e:
        print(f"Error deleting pod: {e}")
        return False
def list_namespaces():
    """列出所有的命名空间"""
    return core_v1.list_namespace()
def get_operations():
    operations = UserOperationLog.query.all()
    return [operation.to_dict() for operation in operations]
def list_controllers(namespace='default', controller_name=None, controller_type=None):
    """列出控制器（Deployment, StatefulSet, DaemonSet）"""
    controllers = {}
    if not controller_name and not controller_type:
        controllers['deployments'] = [d.to_dict() for d in apps_v1.list_namespaced_deployment(namespace).items]
        controllers['stateful_sets'] = [s.to_dict() for s in apps_v1.list_namespaced_stateful_set(namespace).items]
        controllers['daemon_sets'] = [d.to_dict() for d in apps_v1.list_namespaced_daemon_set(namespace).items]
    elif controller_name and not controller_type:
        controllers['deployments'] = [d.to_dict() for d in apps_v1.list_namespaced_deployment(namespace).items if d.metadata.name == controller_name]
        controllers['stateful_sets'] = [s.to_dict() for s in apps_v1.list_namespaced_stateful_set(namespace).items if s.metadata.name == controller_name]
        controllers['daemon_sets'] = [d.to_dict() for d in apps_v1.list_namespaced_daemon_set(namespace).items if d.metadata.name == controller_name]
    elif controller_type and not controller_name:
        if controller_type == 'deployment':
            controllers[controller_type + 's'] = [d.to_dict() for d in apps_v1.list_namespaced_deployment(namespace).items]
        elif controller_type == 'statefulset':
            controllers['stateful_sets'] = [s.to_dict() for s in apps_v1.list_namespaced_stateful_set(namespace).items]
        elif controller_type == 'daemonset':
            controllers['daemon_sets'] = [d.to_dict() for d in apps_v1.list_namespaced_daemon_set(namespace).items]
        else:
            raise ValueError(f"Unsupported controller type: {controller_type}")
    else:
        if controller_type == 'deployment':
            controllers['deployments'] = [d.to_dict() for d in apps_v1.list_namespaced_deployment(namespace).items if d.metadata.name == controller_name]
        elif controller_type == 'statefulset':
            controllers['stateful_sets'] = [s.to_dict() for s in apps_v1.list_namespaced_stateful_set(namespace).items if s.metadata.name == controller_name]
        elif controller_type == 'daemonset':
            controllers['daemon_sets'] = [d.to_dict() for d in apps_v1.list_namespaced_daemon_set(namespace).items if d.metadata.name == controller_name]
        else:
            raise ValueError(f"Unsupported controller type: {controller_type}")
    return controllers
def create_deployment_object(namespace, name, image):
    """创建一个 Deployment 对象"""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [{
                        "name": name,
                        "image": image,
                        "ports": [{"containerPort": 80}]
                    }]
                }
            }
        }
    }

def adjust_time(iso_time):
    """将 ISO 8601 时间字符串转换为 Python datetime 对象"""
    if not iso_time or iso_time == "0001-01-01T00:00:00Z":
        return None
    # 解析 ISO 8601 格式的时间字符串为 datetime 对象，并保留其时区信息
    return datetime.fromisoformat(iso_time.replace('Z', '+00:00')).astimezone(ZoneInfo('Asia/Shanghai'))


def get_configmap(name,namespace):
    try:
        configmap = core_v1.read_namespaced_config_map(name, namespace)
        return configmap
    except client.exceptions.ApiException as e:
        print(f"Error getting ConfigMap: {e}")
        return None
def update_configmap(new_rules):
    try:
        # 获取现有的 ConfigMap
        configmap = get_configmap("prometheus-kubeconfig", "monitor-sa")
        if configmap is None:
            return jsonify({"error": "ConfigMap not found"}), 404

        # 解析现有的 rules.yml 内容
        existing_rules = configmap.data.get('rules.yml', '')
        if not existing_rules:
            return jsonify({"error": "rules.yml not found in ConfigMap"}), 404
        # 解析 YAML 内容
        rules_dict = yaml.safe_load(existing_rules)
        # 添加新的告警规则
        new_alerts = [
            {
                "alert": new_rules.get('alert', ''),
                "expr": new_rules.get('expr', ''),
                "for": new_rules.get('for', ''),
                "labels": {
                    "severity": new_rules.get('severity', '')
                },
                "annotations": {
                    "summary": new_rules.get('summary', ''),
                    "description": new_rules.get('description', '')
                }
            }
        ]
        # 将新告警规则添加到现有的 rules 列表中
        for group in rules_dict['groups']:
            if group['name'] == 'example':
                group['rules'].extend(new_alerts)
                break
        else:
            # 如果没有找到名为 'example' 的组，创建一个新的组
            rules_dict['groups'].append({
                "name": "example",
                "rules": new_alerts
            })
        # 将更新后的 YAML 内容转换为字符串
        updated_rules = yaml.dump(rules_dict, allow_unicode=True)
        # 更新 ConfigMap 的数据
        configmap.data['rules.yml'] = updated_rules
        # 应用更新
        core_v1.patch_namespaced_config_map("prometheus-kubeconfig", "monitor-sa", configmap)

        reload_prometheus()
        return jsonify({"message": "ConfigMap updated successfully"}), 200
    except client.exceptions.ApiException as e:
        print(f"Error updating ConfigMap: {e}")
        return jsonify({"error": str(e)}), 500
#reload prometheus
def reload_prometheus():
    try:
        # 构建 curl 命令
        command = ['curl', '-X', 'POST', 'http://192.168.249.128:31701/-/reload']

        # 执行命令并捕获输出
        result = subprocess.run(command, capture_output=True, text=True)
        # 检查命令是否成功
        if result.returncode == 0:
            print('Prometheus configuration reloaded successfully')
            print(f'Response: {result.stdout}')
        else:
            print(f'Error reloading Prometheus configuration: {result.stderr}')
            print(f'Return code: {result.returncode}')
    except Exception as e:
        print(f'Error executing curl command: {e}')
def insert_or_update_alert(alert_data):
    """插入或更新告警信息"""
    fingerprint = alert_data.get('fingerprint')
    existing_alert = AlertsInfo.query.get(fingerprint)
    startsAt = adjust_time(alert_data['startsAt'])
    endsAt = adjust_time(alert_data['endsAt'])
    if existing_alert:
        # 更新现有记录
        existing_alert.status = alert_data['status']
        existing_alert.startsAt = startsAt
        existing_alert.endsAt = endsAt
        existing_alert.alertname = alert_data['labels']['alertname']
        existing_alert.description = alert_data['annotations'].get('description', '')
        if existing_alert.description == '':
            existing_alert.description = alert_data['labels'].get('log', '')

        existing_alert.severity = alert_data['labels'].get('severity', '')
        existing_alert.instance = alert_data['labels'].get('instance', '')
        existing_alert.job = alert_data['labels'].get('job', '')
        existing_alert.generatorURL = alert_data.get('generatorURL', '')
        existing_alert.updated_at = datetime.now(ZoneInfo('Asia/Shanghai'))
    else:
        # 创建新记录
        new_alert = AlertsInfo(
            fingerprint=fingerprint,
            status=alert_data['status'],
            startsAt=startsAt,
            endsAt=endsAt,
            alertname=alert_data['labels']['alertname'],
            description=alert_data['annotations'].get('description', alert_data['labels'].get('log', '')),
            severity=alert_data['labels'].get('severity', ''),
            instance=alert_data['labels'].get('instance', ''),
            job=alert_data['labels'].get('job', ''),
            generatorURL=alert_data.get('generatorURL', ''),
            updated_at = datetime.now(ZoneInfo('Asia/Shanghai'))
        )
        # print(new_alert)
        db.session.add(new_alert)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e

def delayed_delete(app,fingerprint):
    """延迟删除告警信息"""
    with app.app_context():
        alert = AlertsInfo.query.get(fingerprint)
        if alert:
            db.session.delete(alert)
            try:
                db.session.commit()
                print(f"Alert {fingerprint} has been deleted.")
            except Exception as e:
                db.session.rollback()
                print(f"Error deleting alert {fingerprint}: {e}")
        else:
            print(f"Attempted to delete non-existent alert: {fingerprint}")
def delete_alert(fingerprint):
    """根据指纹结束告警信息并安排延迟删除"""
    alert = AlertsInfo.query.get(fingerprint)
    if alert:
        # 更新 endsAt 字段为当前时间
        alert.endsAt = datetime.now(ZoneInfo('Asia/Shanghai'))
        alert.status = 'resolved'
        try:
            db.session.commit()
            print(f"Updated endsAt for alert {fingerprint}.")
            # 安排一个两分钟后执行的删除任务
            job_id = f'delete_{fingerprint}'
            if not scheduler.get_job(job_id):  # 检查是否已有相同任务
                # 安排一个1分钟后执行的删除任务
                scheduler.add_job(
                    func=delayed_delete,
                    args=[current_app._get_current_object(), fingerprint],
                    trigger='date',
                    run_date=datetime.now(ZoneInfo('Asia/Shanghai')) + timedelta(minutes=1),
                    id=job_id  # 确保每个任务有唯一的 ID
                )
                print(f"Scheduled delayed delete for alert {fingerprint}.")
        except Exception as e:
            db.session.rollback()
            raise e
    else:
        print(f"无此指纹对应告警: {fingerprint}")

def delete_alert_rule(alert_name, namespace='monitor-sa', configmap_name='prometheus-kubeconfig'):
    """删除指定名称的告警规则"""
    try:
        configmap = get_configmap(configmap_name, namespace)
        if configmap is None:
            return R.error().set_message("ConfigMap not found").to_json(), 404

        existing_rules = configmap.data.get('rules.yml', '')
        if not existing_rules:
            return R.error().set_message("rules.yml not found in ConfigMap").to_json(), 404

        rules_dict = yaml.safe_load(existing_rules)
        deleted = False

        for group in rules_dict.get('groups', []):
            if group['name'] == 'example':
                rules_number = len(group.get('rules', []))
                group['rules'] = [rule for rule in group['rules'] if rule.get('alert') != alert_name]
                if len(group.get('rules', [])) < rules_number:
                    deleted = True
                    break

        if not deleted:
            return R.error().set_message(f"Alert '{alert_name}' not found in rules.yml").to_json(), 404

        updated_rules = yaml.dump(rules_dict, allow_unicode=True)
        configmap.data['rules.yml'] = updated_rules
        core_v1.patch_namespaced_config_map(name=configmap_name, namespace=namespace, body=configmap)
        reload_prometheus()  # 如果有这个功能的话

        return R.ok().set_message("Alert rule deleted successfully").to_json()
    except Exception as e:
        print(f"Unexpected error: {e}")
        return R.error().set_message(str(e)).to_json(), 500

def modify_alert_rule(namespace, configmap_name, alert_name, new_rule):
    """修改指定名称的告警规则"""
    try:
        cm = core_v1.read_namespaced_config_map(name=configmap_name, namespace=namespace)
        rules_dict = yaml.safe_load(cm.data.get('alerts.yaml', ''))

        found = False
        for group in rules_dict.get('groups', []):
            for rule in group.get('rules', []):
                if rule.get('alert') == alert_name:
                    rule.update(new_rule)
                    found = True
                    break
            if found:
                break

        if not found:
            return R.error().set_message(f"Alert '{alert_name}' not found").to_json(), 404

        updated_rules_yaml = yaml.dump(rules_dict)
        cm.data['alerts.yaml'] = updated_rules_yaml
        core_v1.patch_namespaced_config_map(name=configmap_name, namespace=namespace, body=cm)

        return R.ok().set_message("Alert rules updated successfully").to_json()
    except (yaml.YAMLError, KeyError) as e:
        return R.error().set_message(f"Failed to parse or serialize ConfigMap data: {e}").to_json(), 500
    except client.exceptions.ApiException as e:
        return R.error().set_message(f"Failed to update ConfigMap: {e}").to_json(), 500

def get_pod_count(podname):
    """获取指定 podname 的 Pod 总数"""
    try:
        response = core_v1.list_pod_for_all_namespaces(field_selector=f"metadata.name={podname}", limit=0)
        return len(response.items) or 0
    except ApiException as e:
        raise Exception(f"Failed to get pod count: {e}")

def get_pod_count_v1():
    """获取指定命名空间下的 Pod 总数"""
    try:
        response = core_v1.list_pod_for_all_namespaces()
        return len(response.items) or 0
    except ApiException as e:
        raise Exception(f"Failed to get pod count: {e}")


def list_pods(podname, page, pageSize):
    """列出指定 podname 的 Pod，并返回分页信息和总数"""
    try:
        if podname:
            # 获取总数
            total_items = get_pod_count(podname)
            print(f"Total items: {total_items}")
            # 计算偏移量
            offset = (page - 1) * pageSize
            # 分页查询数据
            pods = core_v1.list_pod_for_all_namespaces(
                field_selector=f"metadata.name={podname}",
                _preload_content=False,  # 禁用自动解析内容，以便手动处理
                pretty=True,
                limit=total_items,
                _request_timeout=10
            )
        else:
            # 获取所有 Pod 的总数
            total_items = get_pod_count_v1()
            print(f"Total items: {total_items}")
            # 计算偏移量
            offset = (page - 1) * pageSize
            # 分页查询所有 Pod
            pods = core_v1.list_pod_for_all_namespaces(
                _preload_content=False,  # 禁用自动解析内容，以便手动处理
                pretty=True,
                limit=total_items,
                _request_timeout=10
            )

        # 解析 API 响应
        response = client.ApiClient().deserialize(pods, 'V1PodList')
        # 从响应中提取 Pod 列表
        pod_list = [pod.to_dict() for pod in response.items[offset:offset + pageSize]]
        # 构建响应数据
        response_data = {
            'totalItems': total_items,
            'items': pod_list
        }
        return response_data
    except ApiException as e:
        raise Exception(f"Failed to list pods: {e}")

def unsuspend_alert(app,alert_id):
    with app.app_context():
        try:
            alert = AlertsInfo.query.get(alert_id)
            if alert and alert.suspend_status == 'suspended':
                alert.suspend_status = 'unsuspended'
                db.session.commit()
                print(f"Alert {alert_id} has been unsuspended.")
        except Exception as e:
            db.session.rollback()
            print(f"Failed to unsuspend alert {alert_id}: {e}")
def schedule_unsuspend(alert_id, suspend_until_dt):

        try:
            # 确保时间是 aware 的
            if suspend_until_dt is not None:
                parser_time = parser.parse(suspend_until_dt)
                suspend_until_dt = parser_time.astimezone(ZoneInfo('Asia/Shanghai'))
            # 添加一次性任务到调度器
            trigger = DateTrigger(run_date=suspend_until_dt)
            scheduler.add_job(
                unsuspend_alert,
                trigger=trigger,
                args=[current_app._get_current_object(),alert_id],
                id=f'unsuspend_{alert_id}'  # 使用唯一的 job ID 防止重复添加同一任务
            )
            print(f"Scheduled unsuspend for alert {alert_id} at {suspend_until_dt}")
        except Exception as e:
            print(f"Failed to schedule unsuspend for alert {alert_id}: {e}")
def batch_suspend_alerts(alert_ids, suspend_until, reason):
        try:
            # 验证参数
            if not alert_ids or not isinstance(alert_ids, list):
                raise ValueError('无效的ID列表')
            if not suspend_until:
                raise ValueError('必须指定挂起有效期')
            # 将字符串转换为日期时间对象
            parser_time = parser.parse(suspend_until)
            suspend_until_dt=parser_time.astimezone(ZoneInfo('Asia/Shanghai'))
            # 更新数据库
            updated_rows = AlertsInfo.query.filter(AlertsInfo.fingerprint.in_(alert_ids)).update(
                {"suspend_status": "suspended", "suspend_until": suspend_until_dt, "suspend_reason": reason},
                synchronize_session=False
            )
            # return updated_rows
        except (ValueError, SQLAlchemyError) as e:
            raise e

