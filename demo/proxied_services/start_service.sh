#!/usr/bin/env bash
if [[ -n $RBINDER ]]; then
  echo Running with rbinder
  ./rbinder /usr/bin/python3 /code/service.py &
  sleep 2
else
  echo Running without rbinder
  python3 /code/service.py &
fi
envoy -c /etc/service-envoy.yaml --service-cluster service${SERVICE_NAME}
