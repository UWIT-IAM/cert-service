#!/bin/bash

# run the cert expiry notifier

[[ -x /data/local/bin/iam_functions.sh ]] && {
  . /data/local/bin/iam_functions.sh
  ret=check_master iam-tools.u.washington.edu
  [[ ret -eq 1 ]] && {
    echo "not master"
    exit 0
  }
}

echo master
exit 0

cd /logs/cs

date 
export PYTHONPATH=/data/local/lib/python2.6/site-packages/
/usr/local/bin/python2.6 /data/local/bin/certs_warn.pyc -c /data/local/etc/certs_warn.conf

