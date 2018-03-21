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
