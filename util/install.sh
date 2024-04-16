#!/bin/bash

set -x

export PYTHONPATH=/data/local/lib/python2.6/site-packages/
/usr/local/bin/python2.6 install.py

cp certs_warn.sh /data/local/bin
