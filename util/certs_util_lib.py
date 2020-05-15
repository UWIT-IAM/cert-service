# library for the utilities

import json
import re
import smtplib
import psycopg2
import urllib3
import settings

urllib3.disable_warnings()


def _add_owners(owners, url):
    try:
        http = urllib3.PoolManager(cert_file=settings.http_cert_file, cert_reqs='CERT_REQUIRED',
                                   key_file=settings.http_key_file)
        resp = http.request('GET', url)
        jdata = json.loads(resp.data)
        netids = jdata['netids']
        for o in netids:
            if o not in owners:
                owners.add(o)
    except Exception as e:
        print(e)


def _add_netact_host_owners(owners, dns):
    return _add_owners(owners, 'https://api.tools.s.uw.edu/daw/json/DNS_TOOLS/v2/UWNetidsFromFQDN?fqdn=%s' % dns)


def _add_netact_domain_owners(owners, dns):
    return _add_owners(owners, 'https://api.tools.s.uw.edu/daw/json/DNS_TOOLS/v2/UWNetidsFromDomain?domain=%s' % dns)


def _add_gws_domain_owners(owners, dns):
    try:
        http = urllib3.PoolManager(cert_file=settings.http_cert_file, cert_reqs='CERT_REQUIRED',
                                   key_file=settings.http_key_file)
        resp = http.request('GET',
                            settings.gws_url_template % dns)
        jdata = json.loads(resp.data)
        if 'data' in jdata and type(jdata['data']) is list:
            ownerlist = jdata['data']
            for ownerdict in ownerlist:
                if type(ownerdict) is dict and 'type' in ownerdict and ownerdict['id'] not in owners:
                    if ownerdict['type'] == 'uwnetid':
                        owners.add(ownerdict['id'])
                    elif ownerdict['type'] == 'eppn':
                        owners.add(ownerdict['id'])
    except Exception as e:
        print(e)


class CertificateHelper:

    def __init__(self, settings):

        self.db_conn = psycopg2.connect(settings.db_access)
        self.netid_cursor = self.db_conn.cursor()
        self.warn_days = settings.warn_days

        self.mail_server = settings.mail_server
        self.mail_from_addr = settings.mail_from_addr
        self.mail_reply_to = settings.mail_reply_to
        self.mail_tip_text = settings.mail_tip_text

    # find soon to expire certs (30 days)

    def find_expiring(self, warn_day):

        self.netid_cursor.execute(
            "select id, cn, expires from certificate where status=2 and date_trunc('day',expires) = date_trunc('day',now() + interval '%d days');" % (
                warn_day))
        certlist = self.netid_cursor.fetchall()
        return certlist

    # find owners of a cert by favorites
    def find_fav_owners(self, id):
        self.netid_cursor.execute("select netid from owner where id='%s';" % (id))
        owners = self.netid_cursor.fetchall()
        return owners

    # find owners of a dns
    def find_dns_owners(self, dns):
        owners = set()
        # owners.add('mattjm') # use to cc yourself on all notifications
        dots = dns.split(".")
        if len(dots) < 2:
            return owners
        for i in range(len(dots) - 1):
            if i == 0:
                _add_netact_host_owners(owners, dns)
                _add_netact_domain_owners(owners, dns)
                _add_gws_domain_owners(owners, dns)
            else:
                _add_netact_domain_owners(owners, '.'.join(dots[i:]))
                _add_gws_domain_owners(owners, '.'.join(dots[i:]))
        return owners

    # send mail
    def send_mail(self, to_addrs, subject, message):

        mail_text = '\n'.join(['To: %s' % ','.join(to_addrs),
                               'From: %s' % self.mail_from_addr,
                               'Reply-To: %s' % self.mail_reply_to,
                               'Errors-To: %s' % self.mail_reply_to,
                               'X-Auto-Response-Suppress: NDR, OOF, AutoReply',
                               'Precedence: Special-Delivery, never-bounce',
                               'Subject: %s' % subject,
                               '',
                               message,
                               '',
                               self.mail_tip_text])

        # for testing
        # mail_server = smtplib.SMTP_SSL('smtp.washington.edu')
        # mail_server.login('<netid>@uw.edu>', '<password for netid>')
        # mail_server.sendmail(self.mail_from_addr, ['<netid>@uw.edu'], mail_text)
        mail_server = smtplib.SMTP(self.mail_server)
        mail_server.sendmail(self.mail_from_addr, to_addrs, mail_text)
        mail_server.quit()


class AddrHelper:
    regex = re.compile("[^@]+@[^@]+\.[^@]+")

    def uwmail(addr_id):
        return addr_id if AddrHelper.regex.match(addr_id) else addr_id + '@uw.edu'
