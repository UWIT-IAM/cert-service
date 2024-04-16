# show client methods

import sys

# wsdl
from suds.client import Client

from comodo_lib import ComodoSSLClient
from comodo_lib import getOneArg

client,auth = ComodoSSLClient()

arg = getOneArg(False, 'method_name')

if arg!=None:
  method = client.factory.create(arg)
  print(method)

else:

  print(client)
