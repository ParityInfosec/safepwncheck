#!/usr/bin/env python3

import sys,requests,re
from hashlib import sha1

def hashpw (pwd):
    return sha1(pwd.encode('utf-8')).hexdigest()

api='https://api.pwnedpasswords.com/range/'
pword = hashpw(sys.argv[1])

hasha = pword[:5]
hashb = pword[5:]

r = requests.get(api + hasha)
if re.findall(hashb,str(r.content), re.IGNORECASE):
    print("Password: " + sys.argv[1] + " is compromised")
else:
    print("Password: " + sys.argv[1] + " is safe!")
