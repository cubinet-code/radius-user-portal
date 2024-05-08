#!/bin/sh

# config.py is the configuration file
if ! test -f ./config.py ; then
  echo "Please create config.py first!"
  exit 1
fi

if [[ -z "${SERVE_HTTP}" ]]; then
  # server.crt and server.key are self-signed X.509 certificates
  if ! test -f ./server.cer || ! test -f ./server.key ; then
    echo "Please create CSR and CERT first!"
    exit 1
  fi
  gunicorn --certfile=server.cer --keyfile=server.key -w ${WORKERS:-1} --threads ${THREADS:-4} -b :${PORT:-8443} 'portal:app' 
else
  gunicorn -w ${WORKERS:-1} --threads ${THREADS:-4} -b :${PORT:-8443} 'portal:app' 
fi

