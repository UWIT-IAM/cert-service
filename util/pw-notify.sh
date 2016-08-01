#!/bin/bash

# notify interested parties that incommon password should be changed

cd /data/local/cs/util

. ./certlib.sh
exit_if_not_master

/usr/bin/Mail -s "Reset incommon password" iam-support@uw.edu  << END

Reminder to change the InCommon certificate service password
before it expires.  If fox isn't around to do this someone else
will have to.  Instructions in:

 iam-tools:/data/local/cs/util/README.password

You have a week or so to get this done.

END

