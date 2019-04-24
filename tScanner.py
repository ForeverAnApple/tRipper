import ssl
import sys
import time
import random
import pickle
import os
from socket import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from random import getrandbits
from ipaddress import IPv4Address

random.seed(time.time())

# Load the dictionary, if possible
if os.path.exists(os.path.join(os.getcwd(), 'scanned_certs.pkl')):
    with open('scanned_certs.pkl', 'rb') as f:
        certs = pickle.load(f)
else:
    certs = dict()

# Load the set of already tried IPs
if os.path.exists(os.path.join(os.getcwd(), 'scanned_ips.pkl')):
    with open('scanned_ips.pkl', 'rb') as f:
        scannedIps = pickle.load(f)
else:
    scannedIps = set()

print("Loaded", len(certs), "certificate(s) and", len(scannedIps), "scanned IPs.")

VALID_CERTS = 100
print("Attempting to scan for", VALID_CERTS, "valid certificate(s).")

setdefaulttimeout(3) # time is of the essence

i = len(certs)
tries = 0
successful = 0

start = time.time()

def scanIP(ip):
    global i, tries, successful
    
    try:
        print("Scanning:", ip)
        cert = ssl.get_server_certificate((ip, 443))
    except (error, timeout) as err:
        cert = "Timed Out"

    if cert != "Timed Out":
        certs[ip] = cert
        print("Certificate number", len(certs), "extracted from", ip)
        successful += 1
        i += 1
        with open("scanned_certs.pkl", 'wb') as f:
            pickle.dump(certs, f)
    
        with open("scanned_ips.pkl", 'wb') as f:
            pickle.dump(scannedIps, f)
            
    else:
        print(ip, "timed out")
        pass

# Randomly Generate IPs and attempt to obtain a valid SSL 
# certificate off of them
while i < VALID_CERTS:
    tries += 1
    bits = getrandbits(32)
    addr = IPv4Address(bits)
    addr_str = str(addr)
    #print("Trying", addr_str)
    if addr_str not in scannedIps:
        scannedIps.add(addr_str)
        scanIP(addr_str)

if True:
    print("Scanning from hostnames file")
    with open('hostnames_443') as f:
        hostnames = f.readlines()

    hostnames = [h.rstrip('\n') for h in hostnames]

    for name in hostnames:
        if name not in scannedIps and len(name) < 32 and len(name) > 5:
            scannedIps.add(name)
            scanIP(name)

        if len(certs) >= 12000:
            break
        
#print(certs)
print("Tried", tries, "ips for", successful, "successful certificate extractions.")
end = time.time()
print("Scanning for", successful, "valid certificates took", (end-start)/60, "minutes")
print("Total Scanned Certificates:", len(certs))
