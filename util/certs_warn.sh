#!/bin/bash

# run the cert expiry notifier

cd /logs/cs

date 
export PYTHONPATH=/data/local/lib/python2.6/site-packages/
/usr/local/bin/python2.6 /data/local/bin/certs_warn.pyc -c /data/local/etc/certs_warn.conf

