import json
import requests

## This is the policy message
glb_payload = {
  "f1":{
    "policy": {
        "f1-r1": 50,
        "f1-r2": 50,
        "f1-r3": 0
    }
  },
  "f2":{
    "policy": {
      "f2-r1": 100,
      "f2-r2": 0,
      "f2-r3": 0
  }
}
}

glb_url = 'http://localhost:8080/policy'

def send_data(url, payload, headers={'Content-Type': 'application/json'}):
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    print('sent ')
    print(response.text)


send_data(url=glb_url,payload=glb_payload)