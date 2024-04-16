# show a list of owners for a dns

import json

from certs_util_lib import CertificateHelper

import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit
import signal
from optparse import OptionParser

# load configuration

parser = OptionParser()
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-d', '--dns', action='store', type='string', dest='dnsname', help='dns to lookup')
parser.add_option('-p', '--properties', action='store', dest='properties', help='properties')
parser.add_option('-s', '--secrets', action='store', dest='secrets', help='secrets')
options, args = parser.parse_args()

if options.dnsname==None:
    print ('need dns name')
    exit (1)

cs_properties='../cs.properties' if options.properties is None else options.properties
cs_secrets_properties='../cs-secrets.properties' if options.secrets is None else options.secrets
import settings
settings.init(cs_properties, cs_secrets_properties)

certificateHelper = CertificateHelper(settings)

owners = certificateHelper.find_dns_owners(options.dnsname)
for owner in owners:
   print(owner)
