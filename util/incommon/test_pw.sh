#!/bin/bash

# test if comodo password is valid
# looks for a known cert type

cd /data/local/cs/util/incommon
. ../env/bin/activate
res="`python getCertTypes.py | grep 'InCommon Wildcard SSL Certificate'`"

[[ -n $res ]] && {
   echo "password OK"
   exit 0
}
echo "password fails"
exit 1
