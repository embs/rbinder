# Requests Binder (rbinder)

A monitor process who is able to bind incoming and outgoing HTTP requests so
that applications do not need to propagate correlation headers.

## Design goals

- Transparency: no need for app developers modify their code; only deployment
  modifications (may be) required
- Minimal overhead: no significant performance impact over apps being monitored

## What it does

1. listen to key syscalls (`recvfrom`, `sendto`, `fork`, `clone`,...)
2. detect incoming / outgoing HTTP requests in a per-thread basis
3. extract tracing headers from incoming requests & inject them into outgoing
   related requests

## How to use it

Compile

    $ gcc -o rbinder rbinder.c

Run server with rbinder.  Example:

    $ ./rbinder /usr/bin/python server.py

## Complete demo

Scenario

- Two services (1 & 2)
- Service 1 needs requesting something from 2 to fulfill its received requests
- rbinder is used for propagating service 1's tracing headers

Start service 2

    $ PORT=9000 SERVICE_NAME=2 python ./demo/server.py

Start service 1

    $ PORT=9876 SERVICE_NAME=1 ./rbinder /usr/bin/python ./demo/server.py

Request to service 1 with tracing headers

    $ curl -H "X-Request-Id: 12345" localhost:9876

Service 2 output

    WARNING:root:User-Agent: python-requests/2.18.3
    Connection: keep-alive
    Host: localhost:9000
    Accept: */*
    X-Request-Id: 12345
    Accept-Encoding: gzip, deflate

### In a Docker container

    $ docker-compose -f ./demo/docker-compose.yml up -d --build

Request to service 1 with tracing headers

    $ curl -H "X-Request-Id: 12345" localhost:9876

Service 2 logs

    $ docker-compose -f ./demo/docker-compose.yml logs service2

    service2_1  | WARNING:root:Host: service2:9000
    service2_1  | User-Agent: python-requests/2.18.4
    service2_1  | Accept-Encoding: gzip, deflate
    service2_1  | Accept: */*
    service2_1  | Connection: keep-alive
    service2_1  | X-Request-Id: 12345

## Instrumented services demo

*regarding stuff in this [dir](demo/instrumented_services/)*

Scenario

- Front [Envoy][envoy] for generating tracing headers
  - it forwards all incoming requests to service 1
- 2 back-end services (1 & 2)
- Service 1 needs requesting something from 2 to fulfill its received requests
- Code for services instrumented with [py_zipkin][py_zipkin]

### Without rbinder

Scenario

- Service 1 propagate tracing headers by itself

Run

    $ docker-compose -f ./demo/instrumented_services/docker-compose.yml up -d --build

Request

    $ curl localhost:8000

Check Zipkin web interface

    http://localhost:9411/

### With rbinder

Scenario

- rbinder is used for progating headers through service 1 calls

Run

    $ RBINDER=1 docker-compose -f ./demo/instrumented_services/docker-compose.yml up -d --build

Check Zipkin web interface

    http://localhost:9411/

## Proxied services demo

*regarding stuff in this [dir](demo/proxied_services/)*

Scenario

- Front [Envoy][envoy] for generating tracing headers
  - it forwards all incoming requests to service 1
- 2 back-end services (1 & 2)
- Service 1 needs requesting something from 2 to fulfill its received requests
- Spans are sent to [Zipkin][zipkin] through [Envoy][envoy] proxies

### Without rbinder

Scenario

- Service 1 propagate tracing headers by itself

Run

    $ RBINDER='' docker-compose -f ./demo/proxied_services/docker-compose.yml up -d --build

Request

    $ curl localhost:8000

### With rbinder

Scenario

- rbinder is used for progating headers through service 1 calls

Run

    $ RBINDER=1 docker-compose -f ./demo/proxied_services/docker-compose.yml up -d --build

Request

    $ curl localhost:8000

## Acknowledgement

Thanks to [Envoy maintainers][envoy-maintainers] for their inspiring
[examples][envoy-examples].

[envoy]: https://www.envoyproxy.io/
[py_zipkin]: https://github.com/Yelp/py_zipkin/
[envoy-maintainers]: https://github.com/envoyproxy/envoy/blob/2d0e70d3d0b82ed02d514e44fa8b3a52663f3d40/OWNERS.md
[envoy-examples]: https://github.com/envoyproxy/envoy/tree/2d0e70d3d0b82ed02d514e44fa8b3a52663f3d40/examples
[zipkin]: https://zipkin.io/
