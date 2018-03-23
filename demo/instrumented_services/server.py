from flask import Flask
from flask import request

from py_zipkin.util import generate_random_64bit_string
from py_zipkin.zipkin import create_http_headers_for_new_span
from py_zipkin.zipkin import ZipkinAttrs
from py_zipkin.zipkin import zipkin_span

import os
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

def http_transport(encoded_span):
    requests.post(
        'http://zipkin:9411/api/v1/spans',
        data=encoded_span,
        headers={'Content-Type': 'application/x-thrift'},
    )

def extract_zipkin_attrs(headers):
    return ZipkinAttrs(
            headers['X-B3-TraceId'],
            generate_random_64bit_string(),
            headers['X-B3-SpanId'],
            headers.get('X-B3-Flags', ''),
            headers['X-B3-Sampled'],
            )

@app.route('/')
def trace():
    headers = {}
    if not os.getenv('SKIP_INSERVICE_PROPAGATION', False):
        for header in TRACE_HEADERS_TO_PROPAGATE:
            if header in request.headers:
                headers[header] = request.headers[header]

    with zipkin_span(
            service_name='service{}'.format(os.environ['SERVICE_NAME']),
            span_name='service',
            transport_handler=http_transport,
            port=int(os.environ['PORT']),
            zipkin_attrs=extract_zipkin_attrs(request.headers)):
        if int(os.environ['SERVICE_NAME']) == 1 :
            requests.get("http://service2:9000/", headers=headers)

        return ('Hello from service {}!\n'.format(os.environ['SERVICE_NAME']))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ['PORT']), debug=True)
