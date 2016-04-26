#!/bin/bash

# run the cert expiry notifier

. ./certlib.sh
[[ `cron_status certs_warn.sh` == 'backup' ]] && {
   echo "not master"
   exit 0
}

date 
cd /data/local/cs/util
. env/bin/activate
python certs_warn.py

