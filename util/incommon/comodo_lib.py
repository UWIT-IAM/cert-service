# comodo api tools

import sys

# wsdl 
from suds.client import Client

# xml parser
import xml.etree.ElementTree as ET

sslUrl='https://cert-manager.com:443/ws/EPKIManagerSSL?wsdl'
reportUrl='https://cert-manager.com:443/ws/ReportService?wsdl'

def ComodoClient(url):

   client = Client(url)
   authinfo = ET.parse('/data/local/etc/comodo.pw')
   auth = client.factory.create('authData')
   auth.customerLoginUri = authinfo.find('customerLoginUri').text
   auth.login = authinfo.find('login').text
   auth.password = authinfo.find('password').text
   return (client, auth)

def ComodoSSLClient():
   return ComodoClient(sslUrl)
def ComodoReportClient():
   return ComodoClient(reportUrl)


def _usage(req, argtext):
   if req:
      print 'usage: python %s [%s]' % (sys.argv[0], argtext)
   else:
      print 'usage: python %s %s' % (sys.argv[0], argtext)
   exit (1)

# get, verify, and return one arg

def getOneArg(req, argtext):
   if len(sys.argv)>1:
     if sys.argv[1]=='-?' or sys.argv[1]=='-help':
        _usage(req, argtext)
   if req and len(sys.argv)==1:
     _usage(req, argtext)

   if len(sys.argv)==1: return None
   return sys.argv[1]


