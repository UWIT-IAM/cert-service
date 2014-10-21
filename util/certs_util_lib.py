# library for the utilities

# postgres DB classes
import psycopg2

# mailer classes
import smtplib

import subprocess
import dateutil.parser
import string
import time
import re
import os.path
from sys import exit
import signal

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


   def find_dns_owners(self, id):
      owners = []
      proc = subprocess.Popen(['/data/local/bin/all-dns-owners.sh', id], stdout=subprocess.PIPE)
      while True:
        line = proc.stdout.readline().strip()
        if line != '':
           if line.find('@')<0: owners.append(line + '@uw.edu')
           else: owners.append(line)
        else:
           break
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

