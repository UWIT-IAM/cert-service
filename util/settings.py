# Settings for the cert service

# load some info from certservice properties
import ConfigParser
import StringIO
db_access = None
def init(props, secrets):
    global db_access
    pfp = StringIO.StringIO('[base]\n' + open(props, 'r').read() + '\n[secrets]\n' + open(secrets, 'r').read())
    cp = ConfigParser.RawConfigParser()
    cp.readfp(pfp)
    db_access = 'host=%s dbname=%s user=%s password=%s' % \
             (cp.get('base', 'cs.db.host'),  cp.get('base', 'cs.db.name'),  cp.get('base', 'cs.db.user'),  cp.get('secrets', 'cs.db.password'))

warn_days = 30

mail_server = "appsubmit.cac.washington.edu"
mail_from_addr = "UW Certificate Services <somebody@iam-tools.u.washington.edu>"
mail_reply_to = "help@uw.edu"

mail_tip_text = "**Tip**: UW Certificate Services determines ownership of certificate requests and sends email notifications based on contact information in DNS managed by UW-IT. You are receiving this message because you requested this certificate or because you're a registered DNS contact for the certificate's common name or one of its alternative names. Requests for changes to the contact list for your DNS name(s) should be emailed to netops@uw.edu."

mail_warn_text = "Your certificate for '%s', id=%d, will expire in %d days.\n\nIf you intend to continue using this certificate go to UW Certificate Services, https://iam-tools.u.washington.edu/cs/, to renew it."
mail_warn_text_ic = "Your certificate for '%s', id=%d, will expire in %d days.\n\nIf you intend to continue using this certificate go to UW Certificate Services, https://iam-tools.u.washington.edu/cs/, to request a new certificate."

# addrs that don't get mail notices
nomail = set(['netops@uw.edu'])

