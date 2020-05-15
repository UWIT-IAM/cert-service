# send warning to owners of certs soon to expire

import logging
import settings

from optparse import OptionParser

from certs_util_lib import CertificateHelper, AddrHelper

certificateHelper = None

#
# --------------- find and notify of expiring certs -------------
#

logging.basicConfig(filename='certs_warn.log', level=logging.INFO, format='%(asctime)s %(message)s')
logging.getLogger("urllib3").setLevel(logging.WARNING)


def warn_expiring():
    warn_days = settings.warn_days
    warn_text = settings.mail_warn_text

    for warn_day in warn_days:
        certs = certificateHelper.find_expiring(warn_day)
        if len(certs) == 0:
            print('no warnings for', warn_day, 'expirations')
        else:
            for cert in certs:

                owners = certificateHelper.find_dns_owners(cert[1])
                msg = warn_text % (cert[1], cert[0], warn_day)
                to_addrs = set(map(AddrHelper.uwmail, owners.difference(settings.nomail)))
                certificateHelper.send_mail(to_addrs, 'Certificate expiration warning', msg)
                logging.info('sent mail to %s for %s', to_addrs, cert[1])
                print(cert[1] + '\n')


#  
# ---------------- warn main -------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='verbose')
parser.add_option('-p', '--properties', action='store', dest='properties', help='properties')
parser.add_option('-s', '--secrets', action='store', dest='secrets', help='secrets')
options, args = parser.parse_args()

cs_properties = '../cs.properties' if options.properties is None else options.properties
cs_secrets_properties = '../cs-secrets.properties' if options.secrets is None else options.secrets

settings.init(cs_properties, cs_secrets_properties)

certificateHelper = CertificateHelper(settings)

warn_expiring()
