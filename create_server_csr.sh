#!/bin/bash

# Please update server.cnf first with your own information
if ! test -f ./server.cnf ; then
    echo "Please create 'server.cnf' first with your own information"
    exit 1
fi

if ! test -f ./server.key ; then
    echo "Creating new 'server.key' and 'server.csr'"
    openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config server.cnf
else
    echo "Key 'server.key' already exists. Just creating new 'server.csr'"
    openssl req -config server.cnf -new -key server.key -out server.csr
    cat server.csr
fi




