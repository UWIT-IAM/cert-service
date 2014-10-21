#!/bin/bash

dns="$1"

function group_owners {
 webisoget  \
  -text \
  -cert /data/local/etc/urizen3.crt \
  -key /data/local/etc/urizen3.key \
  -cafile /data/local/etc/uwca.crt \
  -header "Accept: text/xml" \
  -url "https://iam-ws.u.washington.edu:7443/group_ws/v2/group/u_weblogin_dns-owners_${1}/effective_member"  | \
 grep 'class="member"' | \
 sed -e '
s/<member .*>\(.*\)<\/member.*/\1/
s/ //g
'
}

{
# by dns
/data/local/bin/domain-owners.pl $dns | grep -v NONE

# by group
while (( 1 ))
do
   # echo "chk: $dns"
   case $dns in
     *.*) group_owners $dns
          ;;
     *) break
   esac
   dns=${dns#*.}
done
} | sort -u

