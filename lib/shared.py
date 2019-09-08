## HOMESCAN SHARED FUNCTIONS
## (c) Copyright Si Dunford, Aug 2019
## Version 1.0.0

# Convert an MQTT return code to an error message
def mqtt_errstr( rc ):
    if rc==0:
        return "Success"
    elif rc==1:
        return "Incorrect protocol version"
    elif rc==2:
        return "Invalid client identifier"
    elif rc==3:
        return "Server unavailable"
    elif rc==4:
        return "Bad username or password"
    elif rc==5:
        return "Not authorised"
    else:
        return "Unknown"

# Create a fixed-width row from dictionary
def row( data, definition, padding=' ' ):
    line = ''
    for col in definition:
        #print( "COL:" + col )
        width = int(definition[col])
        #print( "WIDTH:" + str(width) )
        if col in data:
            field=data[col]
        else:
            field =''
        line+=field.ljust(width,padding)+"  "
    return line

# IP Helper functions
def IP2Integer( ip_str ):
    return struct.unpack( "!L", socket.inet_aton( ip_str ))[0]

def Integer2IP( ip_int ):
    return socket.inet_ntoa( struct.pack( '!L', ip_int ) )

def Mask2CIDR( netmask_str ):
    return sum(bin(int(x)).count('1') for x in netmask_str.split('.'))

