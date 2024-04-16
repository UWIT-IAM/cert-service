# get certificate status

import sys

# wsdl
from suds.client import Client

from comodo_lib import ComodoSSLClient
from comodo_lib import getOneArg

client,auth = ComodoSSLClient()

arg = getOneArg(True, 'cert_id')

result = client.service.getCollectStatus(auth, int(arg))

print(result)
