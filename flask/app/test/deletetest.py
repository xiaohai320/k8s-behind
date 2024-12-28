import requests
url = "http://127.0.0.1:5000/deleterules"
headers = {"Content-Type": "application/json"}
data = {
    "alert_name":'this is a test',
}
response = requests.post(url, headers=headers, json=data)
print(response.status_code)
print(response.text)