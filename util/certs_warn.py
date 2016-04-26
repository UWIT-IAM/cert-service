# send warning to owners of certs soon to expire

import json

import string
import re
from sys import exit
from optparse import OptionParser

from certs_util_lib import CertificateHelper
certificateHelper = None


#
# --------------- find and notify of expiring certs -------------
#

def _uwmail(id):
    return id + '@uw.edu'

def warn_expiring():

   warn_days = settings.warn_days
   warn_text = settings.mail_warn_text

   certs = certificateHelper.find_expiring()
   if len(certs)==0: print 'no warnings'
   for cert in certs:
       owners = certificateHelper.find_dns_owners(cert[1])
       msg = warn_text % (cert[1], cert[0], warn_days)
       # certificateHelper.send_mail(map(_uwmail, owners.difference(settings.nomail)), 'Certificate expiration warning', msg)
       print('would send to {}'.format(map(_uwmail, owners.difference(settings.nomail)), 'Certificate expiration warning', msg))

#  
# ---------------- warn main -------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='verbose')
parser.add_option('-p', '--properties', action='store', dest='properties', help='properties')
parser.add_option('-s', '--secrets', action='store', dest='secrets', help='secrets')
options, args = parser.parse_args()

cs_properties='../cs.properties' if options.properties is None else options.properties
cs_secrets_properties='../cs-secrets.properties' if options.secrets is None else options.secrets
import settings
settings.init(cs_properties, cs_secrets_properties)

certificateHelper = CertificateHelper(settings)

warn_expiring()
