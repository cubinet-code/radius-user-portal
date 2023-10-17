#!/bin/sh

# server.crt and server.key are self-signed X.509 certificates
if ! test -f ./server.cer || ! test -f ./server.key ; then
  echo "Please create CSR and CERT first!"
  exit 1
fi

gunicorn --certfile=server.cer --keyfile=server.key -w 1 --threads 4 -b :8443 -b :8444 'portal:app' 
