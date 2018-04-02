from flask import Flask
from flask import request

import os
import requests

app = Flask(__name__)

@app.route('/')
def trace():
    if int(os.environ['SERVICE_NAME']) == 1 :
        requests.get("http://service2")

    return ('Hello from service {}!\n'.format(os.environ['SERVICE_NAME']))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
