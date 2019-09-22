#!/usr/bin/python

# WAKE ON LAN
# Command line utility
# V1.0, Si Dunford, September 2019

# Uses "wol.py" library file

# NOTE: Linux has a Wake-On-LAN command line tool.
#       This was created to test the library and is not a replacement

import sys
from lib.wol import wakeonlan

if __name__ == '__main__':
    mac = sys.argv[1] if len(sys.argv) > 1 else ''
    ip  = sys.argv[2] if len(sys.argv) > 2 else ''
    if mac=='': 
        print( "Missing argument" )
    else:
        wakeonlan( mac, ip )
    
