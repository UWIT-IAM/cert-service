# library for the utilities

import sys
import dateutil.parser
import string
import time
import re
import os.path
from sys import exit
import signal

import psycopg2
import smtplib


import json
import urllib3

def _add_owners(owners, url):
    try:
        http = urllib3.PoolManager()
        resp = http.request('GET', url)
        jdata = json.loads(resp.data)
        table = jdata['table']
        if not 'row' in table:
            return
        row = table['row']
        if type(row) is dict:
            if row['uwnetid'] not in owners:
                owners.append(row['uwnetid'] + '@uw.edu')
        else:
            for o in row:
                if o['uwnetid'] not in owners:
                    owners.append(o['uwnetid'] + '@uw.edu')
    except Exception as e:
        print e

def _add_host_owners(owners, dns):
    return _add_owners(owners, 'https://umbra.cac.washington.edu/daw/json/DNS/v1/UWNetidsFromFQDN/fqdn/%s' % dns)

def _add_domain_owners(owners, dns):
    return _add_owners(owners, 'https://umbra.cac.washington.edu/daw/json/Net-Contacts/v1/UWNetidsFromDomain/domain/%s' % dns)




class CertificateHelper:

   def __init__(self, config):

      self.db_conn = psycopg2.connect(config['db_access'])
      self.netid_cursor = self.db_conn.cursor()
      self.warn_days = config['warn_days']


      self.mail_server = config['mail_server']
      self.mail_from_addr = config['mail_from_addr']
      self.mail_reply_to = config['mail_reply_to']
      self.mail_tip_text = config['mail_tip_text']

   # find soon to expire certs (30 days)
  
   def find_expiring(self):

      self.netid_cursor.execute("select id,cn,expires from certificate where status=2 and date_trunc('day',expires) = date_trunc('day',now() + interval '%d days');" % (self.warn_days))
      certlist = self.netid_cursor.fetchall()
      for cert in certlist:
         print cert
         
      return certlist

   # find owners of a cert
  
   def find_fav_owners(self, id):

      self.netid_cursor.execute("select netid from owner where id='%s';" % (id))
      owners = self.netid_cursor.fetchall()
      for owner in owners:
         print owner
         
      return owners

   def _add_owners(url):
        global owners
        # try:
        f = urllib.urlopen(url)
        data = f.read()
        f.close()
        jdata = json.loads(data)
        row = jdata['table']['row']
        if type(row) is dict:
            if row['uwnetid'] not in owners:
                owners.append(row['uwnetid'])
        else:
            for o in row:
                if o['uwnetid'] not in owners:
                    owners.append(o['uwnetid'])
        #except urllib3.exceptions.ConnectionError as e:
        #sys.stderr.write()

   def find_dns_owners(self, dns):
       owners = []
       dots = string.split(dns, '.')
       if len(dots) < 2:
          return owners
       for i in range(len(dots)-1):
           if i == 0:
               _add_host_owners(owners, dns)
           else:
               _add_domain_owners(owners, string.join(dots[i:], '.'))
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

      mail_server = smtplib.SMTP(self.mail_server)
      mail_server.sendmail(self.mail_from_addr, to_addrs, mail_text)
      # mail_server.sendmail(self.mail_from_addr,['fox@uw.edu'],'Subject: %s\n\n'%subject+'[sent to: '+','.join(to_addrs)+']\n\n'+ mail_text)
      mail_server.quit()

