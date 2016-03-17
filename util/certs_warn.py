# send warning to owners of certs soon to expire

# json classes
import simplejson as json

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

certificateHelper = None

#
# --------------- find and notify of expiring certs -------------
#


def warn_expiring(config):

   warn_days = config['warn_days']
   warn_text = config['mail_warn_text']

   certs = certificateHelper.find_expiring()
   if len(certs)==0: print 'no warnings'
   for cert in certs:
       owners = certificateHelper.find_dns_owners(cert[1])
       msg = warn_text % (cert[1], cert[0], warn_days)
       certificateHelper.send_mail(owners, 'Certificate expiration warning', msg)



#  
# ---------------- warn main -------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
options, args = parser.parse_args()


config_file = 'certs_warn.conf'
if options.config!=None:
   config_file = options.config
   # print 'using config=' + config_file
f = open(config_file,'r')

config = json.loads(f.read())

certificateHelper = CertificateHelper(config)

warn_expiring(config)
