#!/usr/bin/python

# WAKE ON LAN
# Si Dunford, Sep 2019
# V1.0.2

''' REFERENCE MATERIAL:

AMD WHITE PAPER:
https://www.amd.com/system/files/TechDocs/20213.pdf

PACKET STRUCTURE:
OFS  BYTES  DESCRIPTION
0     6     Synchronization Stream (0xFFFFFF)
6     96    Target MAC (Repeated 16 times)
102   -     Optional 4 or 6 byte password

WIRESHARK CAPTURE FILTER:
ether proto 0x0842 or udp port 9

'''

from socket import socket, AF_INET, SO_BROADCAST, SOCK_DGRAM, SOL_SOCKET

def wakeonlan( mac, ip='' ):
    try:
        mac = bytes.fromhex(mac.replace(":",""))
        stream = b'\xFF'*6
        #print( "STREAM: "+bytes.hex(stream) )
        payload = stream + ( mac * 16 )
        #print( bytes.hex(payload) )
        sck = socket( AF_INET, SOCK_DGRAM )

        if ip: 
            # SEND UDP DIRECT:9 PACKET
            sck.sendto( payload, (ip, 9) )
        else:
            # SEND UDP BROADCAST:9 PACKET
            sck.setsockopt( SOL_SOCKET, SO_BROADCAST, 1 )
            sck.sendto( payload, ('<broadcast>', 9) )

    except Exception as e:
        print( str(e) )
        traceback.print_exc(file=sys.stdout)
    sck.close()
    
# Wake on LAN using eithernet protocol 0x0842
# This doesn't appear to be a standard, but
# is commonly listed as an alternative
def wakeonlanE( src_mac='', dst_mac='', iface='eth1' ):
        
    from socket import AF_PACKET, SOCK_RAW
    sck = socket( AF_PACKET, SOCK_RAW )
    sck.bind( (iface, 0) )

    src      = src_mac.decode( "hex" )
    dst      = dst_mac.decode( "hex" )    
    protocol = "\x08\x42"
    payload  = ('\xFF' * 6) + ( dst * 16 )

    sck.send( dst+src+protocol+payload )
    sck.close()
