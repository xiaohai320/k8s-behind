import app
from flask import Flask, jsonify, Blueprint
import requests

from app.commonutils.R import R

prometheus_bp = Blueprint('prometheus_bp', __name__)
# Prometheus 配置
PROMETHEUS_URL = "http://192.168.249.128:31701/api/v1/query"
# 定义查询语句
MEMORY_USAGE_QUERY = '''
sum(sum(container_memory_working_set_bytes{id="/",kubernetes_io_hostname=~".+"}) by (kubernetes_io_hostname)) 
/ 
sum(machine_memory_bytes{kubernetes_io_hostname=~".+"})
* 100
'''
CPU_USAGE_QUERY = '''
sum(sum(rate(container_cpu_usage_seconds_total{id="/",kubernetes_io_hostname=~".+"}[2m])) by (kubernetes_io_hostname)) 
/ 
sum(machine_cpu_cores{kubernetes_io_hostname=~".+"})
* 100
'''


def get_prometheus_data(query):
    """调用 Prometheus API 获取数据"""
    response = requests.get(PROMETHEUS_URL, params={"query": query})
    if response.status_code != 200:
        raise Exception(f"Prometheus API error: {response.status_code}, {response.text}")

    data = response.json()
    if data["status"] != "success":
        raise Exception(f"Prometheus query failed: {data}")

    # 提取结果值
    result = data["data"]["result"]
    if not result:
        return 0.0  # 默认值
    return float(result[0]["value"][1])  # 返回数值


@prometheus_bp.route('/api/cluster-usage', methods=['GET'])
def get_cluster_usage():
    try:
        # 获取集群内存使用率
        memory_usage = get_prometheus_data(MEMORY_USAGE_QUERY)

        # 获取集群 CPU 使用率
        cpu_usage = get_prometheus_data(CPU_USAGE_QUERY)
        print("memory_usage", memory_usage)
        print("cpu_usage", cpu_usage)
        # 返回 JSON 数据
        return R.ok().set_data({"memoryUsage": memory_usage, "cpuUsage": cpu_usage}).to_json()
    except Exception as e:
        return R.error().set_message(str(e)).to_json()