#!/bin/bash

# notify interested parties that incommon password should be changed

. ./certlib.sh
[[ `cron_status certs_warn.sh` == 'backup' ]] && {
   echo "not master"
   exit 0
}

/usr/sbin/sendmail -f "iam-tools" -t  << END
To: iam-support@uw.edu
Subject: Reset incommon password

Reminder to change the InCommon certificate service password 
before it expires.  If fox isn't around to do this someone else 
will have to.  Instructions in:

 iam-tools:/data/local/cs/util/README.password

You have a week or so to get this done.

END

