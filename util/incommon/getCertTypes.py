# get available cert types

# wsdl 
from suds.client import Client

from comodo_lib import ComodoSSLClient

client,auth = ComodoSSLClient()

result = client.service.getCustomerCertTypes(auth)

print(result)
