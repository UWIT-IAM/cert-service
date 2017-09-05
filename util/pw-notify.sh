#!/bin/bash

# notify interested parties that incommon password should be changed

cd /data/local/cs/util

. ./certlib.sh
exit_if_not_master

/usr/bin/Mail -s "Reset incommon password" iam-support@uw.edu  << END

Forward to IAM Certificate Services.

Reminder to change the InCommon certificate service password
before it expires.  Matt, this means you.  Instructions in:

   iam-tools:/data/local/cs/util/README.password

on either iamtools11 or iamtools12.

You have a week or so to get this done.

END

