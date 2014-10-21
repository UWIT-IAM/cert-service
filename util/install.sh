#!/bin/bash

set -x 

export PYTHONPATH=/data/local/lib/python2.6/site-packages/
/usr/local/bin/python2.6 install.py 

cp certs_warn.sh /data/local/bin
cp all-dns-owners.sh /data/local/bin
cp certs_warn.conf /data/local/etc

