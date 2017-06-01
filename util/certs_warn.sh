#!/bin/bash

# function to send message to dash
# args: severity host idp|gateway message
function send_dash () {
  sev=$1
  host=$2
  type=$3
  msg="$4"

  xml="<Alert><Action>Post</Action>
    <ProblemHost>$host</ProblemHost>
    <Component>$type</Component>
    <Severity>$sev</Severity>
    <Contact>Identity and Access Management</Contact>
    <Msg><![CDATA[$msg]]></Msg>
    </Alert>"

  echo $xml > /dev/udp/localhost/8341
}


# run the cert expiry notifier

cd /data/local/cs/util

. ./certlib.sh
exit_if_not_master

. env/bin/activate
certs="`python certs_warn.py`"
if [ "$?" -ne 0 ]
then
  send_dash "6" "iam-tools.u.washington.edu" "certnotify" "Cert expiration warning failed"
fi

send_mail mattjm@uw.edu "expire certs notices" "$certs"

# send message to dash
# args: severity host idp|gateway message
function send_dash {
  sev=$1
  host=$2
  type=$3
  msg="$4"

  xml="<Alert><Action>Post</Action>
    <ProblemHost>$host</ProblemHost>
    <Component>$type</Component>
    <Severity>$sev</Severity>
    <Contact>Identity and Access Management</Contact>
    <Msg><![CDATA[$msg]]></Msg>
    </Alert>"

  echo $xml > /dev/udp/localhost/8341
}

