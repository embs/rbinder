# Requests Binder (rbinder)

A monitor process who is able to bind incoming and outgoing HTTP requests so
that applications do not need to propagate correlation headers.

## Design goals

- Transparency: no need for app developers modify their code; only deployment
  modifications (may be) required
- Minimal overhead: no significant performance impact over apps being monitored

## How it may come to work

1. listen to key syscalls (`recvfrom`, `sendto`, `fork`, `clone`,...)
2. detect incoming / outgoing HTTP requests in a per-thread basis
3. write log file with requests binding
