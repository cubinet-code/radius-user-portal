#!/bin/sh

# ansible-playbook -i 127.0.0.1, ansible-portal.yaml -e ansible_connection=local

# Create python venv
python3 -m venv venv
. venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements.txt

if ! test -f ./config.py ; then
    cp config.example.py config.py
fi

if ! test -f ./server.cnf ; then
    cp server.example.cnf server.cnf
fi

if test -f ./portal.service ; then
    # activate systemd service
    # Make sure you edit the path in service file before
    sudo cp portal.service /etc/systemd/system/portal.service
    sudo systemctl daemon-reload
    # activate service on system startup
    sudo systemctl enable portal
    sudo systemctl restart portal
fi