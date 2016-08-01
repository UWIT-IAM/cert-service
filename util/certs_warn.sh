#!/bin/bash

# run the cert expiry notifier

cd /data/local/cs/util

. ./certlib.sh
exit_if_not_master

. env/bin/activate
python certs_warn.py >> cert_warn.log

