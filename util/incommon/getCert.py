# get one certificate by id

import sys

# wsdl 
from suds.client import Client

from comodo_lib import ComodoSSLClient
from comodo_lib import getOneArg

client,auth = ComodoSSLClient()

arg = getOneArg(True, 'cert_id')
  
result = client.service.collect(auth, int(arg), 1)

print(result)
