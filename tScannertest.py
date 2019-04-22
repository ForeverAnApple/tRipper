import ssl
from socket import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

setdefaulttimeout(5)

try:
  cert = ssl.get_server_certificate(("98.137.246.71", 443))
except (error, timeout) as err:
  print("No connection: {0}".format(err))
  exit()
  

print(cert.encode())
key = x509.load_pem_x509_certificate(cert.encode(), default_backend())
keyPub = key.public_key()
print('Extracted Public Key:', keyPub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
print('n:', keyPub.public_numbers().n, '\ne:', keyPub.public_numbers().e)
