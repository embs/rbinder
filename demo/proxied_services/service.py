from flask import Flask
from flask import request
import socket
import os
import sys
import requests

app = Flask(__name__)

TRACE_HEADERS_TO_PROPAGATE = [
    'X-Ot-Span-Context',
    'X-Request-Id',
    'X-B3-TraceId',
    'X-B3-SpanId',
    'X-B3-ParentSpanId',
    'X-B3-Sampled',
    'X-B3-Flags'
]

@app.route('/')
def trace():
    headers = {}
    if int(os.environ['SERVICE_NAME']) == 1 :
        if not os.getenv('SKIP_INSERVICE_PROPAGATION', False):
            for header in TRACE_HEADERS_TO_PROPAGATE:
                if header in request.headers:
                    headers[header] = request.headers[header]
        requests.get("http://localhost:9000/", headers=headers)
    return ('Hello from behind Envoy (service {})! hostname: {} resolved'
            'hostname: {}\n'.format(os.environ['SERVICE_NAME'], 
                                    socket.gethostname(),
                                    socket.gethostbyname(socket.gethostname())))

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)
