import requests
url = "http://127.0.0.1:5000/modifyrules"
headers = {"Content-Type": "application/json"}
data = {
"modify_alert_name":"this is a test",
"modify_alert_rules":{
    "alert":'this is not a test',
    "expr":"process_open_fds{job=~'kubernetes-kube-proxy'} > 1000",
    "for":"10s" ,
    "severity": "test",
    "summary": "111",
    "description":"1111"}
}
response = requests.post(url, headers=headers, json=data)
print(response.status_code)
print(response.text)