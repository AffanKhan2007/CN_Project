#!/usr/bin/env bash
# Tested target: Ubuntu 20.04 (Python 3.8). Newer Python versions need the pins below.
set -e
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-pip
# Ryu needs Python 3.8/3.9: use a venv, e.g.
#   uv venv --python 3.9 ~/ryu-env && uv pip install --python ~/ryu-env/bin/python -r requirements.txt
