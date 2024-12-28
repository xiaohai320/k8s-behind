import requests
url = "http://127.0.0.1:5000/addrules"
headers = {"Content-Type": "application/json"}
data = {
    "alert":'this is a test',
    "expr":"process_open_fds{job=~'kubernetes-kube-proxy'} > 1000",
    "for":"10s" ,
    "severity": "test",
    "summary": "111",
    "description":"1111"
}
response = requests.post(url, headers=headers, json=data)
print(response.status_code)
print(response.text)