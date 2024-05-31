# Settings for the cert service

# load some info from certservice properties
import configparser
import io

db_access = None
http_cert_file = None
http_key_file = None
gws_url_template = None

def init(props, secrets):
    global db_access
    global http_cert_file
    global http_key_file
    global gws_url_template

    pfp = io.StringIO('[base]\n' + open(props, 'r').read() + '\n[secrets]\n' + open(secrets, 'r').read())
    cp = configparser.RawConfigParser()
    cp.read_file(pfp)
    ssl_key = cp.get('base', 'cs.db.sslkey').replace('.raw', '')
    db_access = 'host=%s dbname=%s user=%s password=%s sslkey=%s sslcert=%s sslrootcert=%s sslmode=require' % \
                (cp.get('base', 'cs.db.host'), cp.get('base', 'cs.db.name'), cp.get('base', 'cs.db.username'),
                 cp.get('secrets', 'cs.db.password'), ssl_key, cp.get('base', 'cs.db.sslcert'),
                 cp.get('base', 'cs.db.sslrootcert'))
    http_cert_file = cp.get('base', 'cs.webclient.certFile')
    http_key_file = cp.get('base', 'cs.webclient.keyFile')
    gws_url_template = cp.get('base', 'cs.gws.urltemplate')

warn_days = (7, 30)

mail_server = "appsubmit.cac.washington.edu"
mail_from_addr = "UW Certificate Services <somebody@iam-tools.u.washington.edu>"
mail_reply_to = "help@uw.edu"

mail_tip_text = "**Tip**: UW Certificate Services determines ownership of certificate requests and sends email notifications based on contact information in DNS managed by UW-IT. You are receiving this message because you requested this certificate or because you're a registered DNS contact for the certificate's common name or one of its alternative names. Requests for changes to the contact list for your DNS name(s) should be emailed to netops@uw.edu."

mail_warn_text = "Your certificate for '%s', id=%d, will expire in %d days.\n\nIf you intend to continue using this certificate go to UW Certificate Services, https://iam-tools.u.washington.edu/cs/, to renew it."
mail_warn_text_ic = "Your certificate for '%s', id=%d, will expire in %d days.\n\nIf you intend to continue using this certificate go to UW Certificate Services, https://iam-tools.u.washington.edu/cs/, to request a new certificate."

# addrs that don't get mail notices
nomail = set(['netops@uw.edu'])
