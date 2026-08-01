#!/bin/sh

sudo apt update
sudo apt install frr frr-pythontools
sudo apt install bridge-utils
export PATH=$PATH:/usr/lib/frr

python3 -m venv "$(dirname "$0")"/../venv
"$(dirname "$0")"/../venv/bin/pip install -r "$(dirname "$0")"/../requirements.txt
"$(dirname "$0")"/../venv/bin/pip install --upgrade git+https://github.com/cnp3/ipmininet.git@v1.1
