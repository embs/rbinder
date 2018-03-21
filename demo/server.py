from flask import Flask
from flask import request
import os
import sys
import requests
import logging

app = Flask(__name__)

@app.route('/')
def trace():
    logging.warning(request.headers)
    # call service 2 from service 1
    if int(os.environ['SERVICE_NAME']) == 1 :
        ret = requests.get("http://localhost:9000/")
    return ('Hello from service {}!\n'.format(os.environ['SERVICE_NAME']))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ['PORT']), debug=True)
