import requests

response = requests.get("https://example.com/status")
print(response.status_code)

