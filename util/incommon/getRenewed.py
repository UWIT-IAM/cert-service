# get a renewed certificate by renewid

import sys
import logging
logging.basicConfig()

# wsdl 
from suds.client import Client

from comodo_lib import ComodoSSLClient
from comodo_lib import getOneArg

client,auth = ComodoSSLClient()

arg = getOneArg(True, 'renew_id')
  
print '[%s]' % arg

result = client.service.collectRenewed(arg, 1)

print result
