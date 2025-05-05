import time

import requests
from flask import Blueprint

from app.commonutils.R import R

# 定义蓝图
prometheus_bp = Blueprint('prometheus_bp', __name__)

# Prometheus 配置
PROMETHEUS_URL = "http://192.168.249.128:31701/api/v1/query"
PROMETHEUS_RANGE_URL = "http://192.168.249.128:31701/api/v1/query_range"

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

NODE_UPTIME_QUERY = '''
time() - node_boot_time_seconds
'''

IOWAIT_QUERY_RANGE = """
    avg by (instance) (
      irate(node_cpu_seconds_total{mode="iowait"}[5m]) * 100
    )
    """
FILE_DESCRIPTORS_QUERY = '''
node_filefd_allocated{}
'''

# 内存使用率查询
MEMORY_USAGE_QUERY_RANGE = """
    avg by (instance) (
  (node_memory_MemTotal_bytes - node_memory_MemFree_bytes - node_memory_Buffers_bytes - node_memory_Cached_bytes) 
  / node_memory_MemTotal_bytes 
  * 100
)
    """
CPU_USAGE_QUERY_RANGE = "avg by (instance) (100 - (rate(node_cpu_seconds_total{mode='idle'}[5m]) * 100))"

# 网络传输速率查询（修正后的）
NETWORK_TX_QUERY = """
sum by (instance) (
  rate(node_network_transmit_bytes{device!~"lo|docker.*|br.*"}[2m])
) * 8  # 转换为bps
"""

# 网络接收速率查询
NETWORK_RX_QUERY = """
sum by (instance) (
  rate(node_network_receive_bytes{device!~"lo|docker.*|br.*"}[2m])
) * 8  # 转换为bps
"""

# 丢包率查询（修正后的）
NETWORK_LOSS_QUERY = """
sum by (instance) (
  ( 
    rate(node_network_transmit_packets{device!~"lo|docker.*|br.*"}[2m]) 
    - rate(node_network_transmit_packets_dropped{device!~"lo|docker.*|br.*"}[2m]) 
  ) 
  /
  rate(node_network_transmit_packets{device!~"lo|docker.*|br.*"}[2m])
) * 100
"""

# 网络错误查询（按类型分类）
NETWORK_ERRORS_QUERY = '''
sum by (instance, type) (
  rate(node_network_errors{device!~"lo|docker.*|br.*"}[2m])
)
'''


def get_prometheus_data_range(query, end,start, step):
    """调用 Prometheus API 获取范围数据"""
    params = {
        "query": query,
        "start": start,
        "end": end,
        "step": step
    }
    response = requests.get(PROMETHEUS_RANGE_URL, params=params)
    if response.status_code != 200:
        raise Exception(f"Prometheus API error: {response.status_code}, {response.text}")

    data = response.json()
    if data["status"] != "success":
        raise Exception(f"Prometheus query failed: {data}")

    # 提取时间序列数据（按实例分组）
    result = data["data"]["result"]
    if not result:
        return []  # 默认返回空列表

    # 将数据转换为时间序列格式（[[timestamp, value], ...]）
    # 假设查询返回多个实例，需要按实例分开处理
    # 这里假设查询返回的数据是按实例分组的
    formatted_data = []
    for series in result:
        instance = series["metric"].get("instance", "unknown")
        values = series["values"]
        formatted_data.append({
            "instance": instance,
            "values": values  # 时间序列数据
        })

    return formatted_data


def get_prometheus_data(query):
    """调用 Prometheus API 获取数据（支持多实例返回）"""
    response = requests.get(PROMETHEUS_URL, params={"query": query})
    if response.status_code != 200:
        raise Exception(f"Prometheus API error: {response.status_code}, {response.text}")

    data = response.json()
    if data["status"] != "success":
        raise Exception(f"Prometheus query failed: {data}")

    result = data["data"]["result"]
    if not result:
        return []  # 返回空列表表示无数据
    # 返回结构化数据（按实例和类型分组）
    return [
        {
            "instance": item["metric"].get("instance", "unknown"),
            "type": item["metric"].get("type", "unknown"),
            "value": float(item["value"][1])
        }
        for item in result
    ]

def get_prometheus_data_only(query):
    """调用 Prometheus API 获取数据（支持多实例返回）"""
    response = requests.get(PROMETHEUS_URL, params={"query": query})
    if response.status_code != 200:
        raise Exception(f"Prometheus API error: {response.status_code}, {response.text}")
    data = response.json()
    if data["status"] != "success":
        raise Exception(f"Prometheus query failed: {data}")

    result = data["data"]["result"]
    return result


@prometheus_bp.route('/cluster-usage', methods=['GET'])
def get_cluster_usage():
    try:
        # 获取集群内存使用率
        memory_usage = get_prometheus_data_only(MEMORY_USAGE_QUERY)
        now = int(time.time())

        # 获取集群 CPU 使用率
        cpu_usage = get_prometheus_data_only(CPU_USAGE_QUERY)
        cpu_usage_range = get_prometheus_data_range(CPU_USAGE_QUERY_RANGE, now, now - 30 * 60, 60)
        memory_usage_range = get_prometheus_data_range(MEMORY_USAGE_QUERY_RANGE, now, now - 30 * 60, 60)
        network_tx_range = get_prometheus_data_range(
            NETWORK_TX_QUERY,
            now, now - 30 * 60, 60
        )

        # 网络接收速率（RX）
        network_rx_range = get_prometheus_data_range(
            NETWORK_RX_QUERY,
            now, now - 30 * 60, 60
        )

        # 网络丢包率
        network_loss_range = get_prometheus_data_range(
            NETWORK_LOSS_QUERY,
            now, now - 30 * 60, 60
        )

        # 网络错误（按类型分类）
        network_errors = get_prometheus_data(NETWORK_ERRORS_QUERY)
        # 获取节点运行时间
        node_uptime = get_prometheus_data(NODE_UPTIME_QUERY)

        # 获取节点 iowait
        node_iowait = get_prometheus_data_range(IOWAIT_QUERY_RANGE, now, now - 30 * 60, 60)

        # 获取打开的文件描述符
        file_descriptors = get_prometheus_data(FILE_DESCRIPTORS_QUERY.replace("$node", "k8s-master"))

        # 返回 JSON 数据
        return R.ok().set_data({
            "memoryUsage": memory_usage,
            "cpuUsage": cpu_usage,
            "nodeUptime": node_uptime,
            "nodeIowait": node_iowait,
            "fileDescriptors": file_descriptors,
            "cpuUsageRange": cpu_usage_range,
            "memoryUsageRange": memory_usage_range,
            "networkTx": network_tx_range,
            "networkRx": network_rx_range,
            "networkLoss": network_loss_range,
            "networkErrors": network_errors
            # "
            # "cpuDiskIoData": cpu_disk_io_data
        }).to_json()

    except Exception as e:
        return R.error().set_message(str(e)).to_json()