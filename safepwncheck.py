#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = "Justin Cornwell"
__credits__ = ["Justin Cornwell", "Parity InfoSec LLC"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Justin Cornwell"
__email__ = "info@parityinfosec.com"
__status__ = "Production"


import sys,requests,re,argparse
from hashlib import sha1
from colorama import Fore, Style

api='https://api.pwnedpasswords.com/range/'

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'   _____       ____     ____                 ________              __ \n'
    SIG += '  / ___/____ _/ __/__  / __ \_      ______  / ____/ /_  ___  _____/ /__\n'
    SIG += '  \__ \/ __ `/ /_/ _ \/ /_/ / | /| / / __ \/ /   / __ \/ _ \/ ___/ //_/\n'
    SIG += ' ___/ / /_/ / __/  __/ ____/| |/ |/ / / / / /___/ / / /  __/ /__/ ,<   \n'
    SIG += '/____/\__,_/_/  \___/_/     |__/|__/_/ /_/\____/_/ /_/\___/\___/_/|_|  \n'
    SIG += '\n#####################################################################'+RS+'\n'
    SIG += '# '+Fore.BLUE+' Author: Justin Cornwell, Parity InfoSec '+RS+'#########################'+RS+'\n'
    SIG += '\n#####################################################################'+RS+'\n'
    return SIG

def checkpw (p):
    hash = sha1(p.encode('utf-8')).hexdigest()
    hasha = hash[:5]
    hashb = hash[5:]

    r = requests.get(api + hasha)
    if re.findall(hashb,str(r.content), re.IGNORECASE):
        print(Fore.RED + "[-] Password: " + p + " is compromised")
    else:
        print(Fore.GREEN + "[+] Password: " + p  + " is safe!")

def main(args):
    if args.passwd:
        checkpw(args.passwd)
    else:
        with open(args.pwfile) as fin:
            for line in fin:
                checkpw(line.rstrip('\n'))

if __name__ == "__main__":
    print(header())
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pass", action="store", dest="passwd", help="single password mode")
    group.add_argument("-f", "--file", action="store", dest="pwfile", help="provide password file for batch testing")
    if len(sys.argv) == 1:
        parser.print_help()
    args = parser.parse_args()

    main(args)
