## HOMESCAN: Network ARP Scan and Sniff
## (c) Copyright Si Dunford, Aug 2019
## Version 1.0.1

# Imports
from scapy.all import *
import socket, fcntl
import struct, traceback
import time, datetime
import paho.mqtt.client as pahomqtt
import json
import logging
from lib.settings import settings
from lib.shared import *

# LOGGING
log = logging.getLogger( "homescan" )
handler = logging.FileHandler( 'homescan.log' )
formatter = logging.Formatter( '%(asctime)s %(levelname)s %(message)s' )
handler.setFormatter(formatter)
log.setLevel(logging.DEBUG)     # USE THIS DURING DEVELOPMENT
#log.setLevel(logging.INFO)     # USE THIS AFTER PUBLICATION
log.addHandler(handler)

SCAN_DELAY = 60     # Wait 60 seconds before starting next SCAN/REAP
VERBOSE = False     # By default, don't do verbose logging

# Device list
devices = {}
address = {}
Running = True

# Milliseconds function for RTT calculation
millisecs = lambda: time.time() * 1000

# Get local IP address
def localAddress( iface ):
    #print( iface )
    interface = bytes( iface[:15], 'utf-8' )
    return socket.inet_ntoa(
        fcntl.ioctl(
            socket.socket( socket.AF_INET, socket.SOCK_DGRAM ),
            0x8915,     # SIOCGIFADDR
            struct.pack( '256s', interface[:15] )
            )[20:24])

# Get local subnet mask
def localMask( iface ):
    interface = bytes( iface[:15], 'utf-8' )
    return socket.inet_ntoa(
        fcntl.ioctl( 
            socket.socket( socket.AF_INET, socket.SOCK_DGRAM ), 
            0x891B,     # SIOCGIFNETMASK
            struct.pack( '256s', interface )
            )[20:24])
    
# Handler for ARP Packet Sniffer
def arp_handler(packet):
    #print( packet[ARP].psrc )
    if packet[ARP].op == 1: #ARP.who_has:       # ARP REQUEST
        # We don't need these at the moment
        #print( "o "+packet[ARP].pdst+" at "+str(millisecs()) )
        address[packet[ARP].pdst]=millisecs()
        #print(ls(packet))
        #print(packet[Ether].src, "has IP", packet[ARP].pdst)
        pass
    elif packet[ARP].op == 2: #ARP.is_at:     # ARP REPLY
        ip_str = packet[ARP].psrc
        mac    = packet[Ether].src
        try:
            hostbyaddr = socket.gethostbyaddr(ip_str)
            hostname   = hostbyaddr[0]
        except:
            hostname   = ''
        rtt = "{0:.3f}".format( millisecs()-address[ip_str] )
        #print( "i "+ip_str+" at "+str(millisecs())+" ("+str(rtt)+")")
        mac_found( mac, ip_str, hostname, rtt )
    return
            
# MAC Address Sniffer Results
def mac_found( mac, ip, hostname, rtt ):
    # Check if in list
    if mac in devices:
        # MAC address is already known
        device = devices[mac]
        # Reset Timeout counter to zero
        device["counter"]=0
        device["rtt"]=rtt
        device["timeout"]=False
        # If device status up, re-publish it so that RTT is included
        if device['state']=="up":
            # Update MQTT
            mqtt_publish_device( device )
        elif device['state']=="down":
            # Set State to online
            device['state']="up"
            # Update MQTT
            mqtt_publish_device( device )
            # Send ONLINE event
            mqtt_publish_event( "ONLINE", mac, ip, hostname )
        else:
            # State= unknown, or invalid
            # Set State to online
            device['state']="up"
            # Update MQTT (Only if not already up)
            if not device['prestate']=='up':
                mqtt_publish_device( device )
                device['prestate']=='up'
            # Do not send an event
            
        # Check for changes in IP adress and Hostname
        if not device["ip"]==ip:    # Device IP address has changed (Probably DHCP)
            # Send CHANGE event
            mqtt_publish_event( "CHANGE", mac, ip, hostname, "Previously "+device["ip"] )
            # Update device
            device["ip"]=ip
            # Update MQTT
            mqtt_publish_device( device )
        if not devices[mac]["hostname"]==hostname:  # Hostname changed!
            # Send CHANGE event
            mqtt_publish_event( "CHANGE", mac, ip, hostname, "Previously "+device["hostname"] )
            # Update device
            device["hostname"]=hostname
            # Update MQTT
            mqtt_publish_device( devices )
    else:
        # MAC address is not previously known
        device = {"mac":mac, "ip":ip, "hostname":hostname, "state":"up", "counter":0, "timeout":False, "rtt":rtt }
        # Add to Device list
        devices[mac]= device
        # Publish device into MQTT
        mqtt_publish_device( device )
        # Raise an ARRIVE event
        mqtt_publish_event( "ARRIVE", mac, ip, hostname )
        
# MAC Address expiration
#def mac_expire( mac, ip, hostname ):
#    # MAC address has expired / Device is down
#    devices[mac]['state']=='down'
#    mqtt_publish_event( "OFFLINE", mac, ip, hostname )
#    mqtt_publish_device( devices[mac] )

# MAC Address deletion
#def mac_delete( mac, ip, hostname ):
#    # MAC address is  zombie and can be deleted
#    mqtt_publish_event( "DELETE", mac, ip, hostname )
#    mqtt.publish( TOPIC+"/"+mac, "", qos=0, retain=True )   # Delete Retained Message
    
# MQTT connection
def mqtt_on_connect( client, userdata, flags, rc ):
    if rc==0 :
        if VERBOSE: log.debug( "* MQTT connected OK")
        # Subscribe on connect so that subscriptions will recover disconnect
        client.subscribe(settings.topic+"/#")
        if VERBOSE: log.debug( "* Subscribed to '"+settings.topic+"/#'")
        # Set Application state to online
        mqtt_publish_state( settings.online )
    else:
        if VERBOSE: log.debug( "* MQTT connection failed: ["+str(rc)+"] "+mqtt_errstr(rc) )

def mqtt_on_disconnect( client, userdata, rc ):
    if VERBOSE: log.debug( "* MQTT disconnected: ["+str(rc)+"] "+mqtt_errstr(rc) )

def mqtt_on_message( client, userdata, msg ):
    try:
        if msg.retain==1:
            decoded = str( msg.payload.decode("utf-8","ignore") )
            data = json.loads( decoded )
            #print( "Loading "+decoded )
            if not "mac" in data: return
            device = {}
            device['mac']=data["mac"] if "mac" in data else ""
            if device['mac']=="" or device['mac'] in devices: return
            device['ip']=data["ip"] if "ip" in data else ""
            if device['ip']=='': return
            # Get optional information
            device['hostname']=data["hostname"] if "hostname" in data else ""
            device['prestate']=data["state"] if "state" in data else "unknown"
            # Other variables.
            device['counter']=0
            device['rtt']="-1"
            device['state']="unknown"
            device["timeout"]=False
            # Publish a "loaded" event for this device
            mqtt_publish_event( "LOADED", device['mac'], device['ip'], device['hostname'] )
            devices[device['mac']]=device
        # We don't bother with non-retained messages here
        # (These will be published by ourself anyway)
    except Exception as e:
        #if VERBOSE: print( "** Something went wrong!" )
        if VERBOSE: log.debug( str(e) )
        if VERBOSE: traceback.print_exc(file=sys.stdout)
        logging.exception(e)
        
def mqtt_publish_device( device ):
    data = { "mac":device['mac'], "ip":device['ip'], "hostname":device['hostname'], "state":device['state'], "rtt":device['rtt'] }
    msg = json.dumps( data, default=str )
    mqtt.publish( settings.topic+"/"+device['mac'], msg, qos=0, retain=True )

def mqtt_publish_event( event, mac, ip, hostname, info='' ):
    message = { "event":event, "mac":mac, "ip":ip, "hostname":hostname, "info":info }
    msg = json.dumps( message, default=str )
    mqtt.publish( settings.events, msg, qos=0 )

def mqtt_publish_state( state ):
    #client.publish( settings.state, json.dumps( {"state":settings.online}, default=str ), qos=0, retain=True )
    message = { "state":state }
    msg = json.dumps( message, default=str )
    mqtt.publish( settings.state, msg, qos=0 )
    
class HomeScan():
        
    def run( self ):
        global Running
        
        # Work out addresses to scan 
        if( settings.subnet=="" ):
            log.debug( "* Calculating address/mask" )
            ip_int    = IP2Integer( localAddress( settings.interface ) )
            mask_int  = IP2Integer( localMask( settings.interface ) )
        else:
            log.debug( "* Reading address/mask from config" )
            ip_int    = IP2Integer( settings.subnet )
            mask_int  = IP2Integer( settings.mask )    
        hosts     = 4294967295 - mask_int
        network   = ip_int & mask_int
        broadcast = network + hosts

        # Do some logging to help in debugging issues
        cidr = Integer2IP( network )+"/"+str(Mask2CIDR( Integer2IP( mask_int ) ))
        log.debug( "SUBNET: "+cidr )

        #print( "MY MAC:    "+Ether().src )
        #print( "SUBNET: "+cidr )
        #print( "SUBNET: "+Integer2IP( network ) )
        #print( "MASK:   "+Integer2IP( mask_int ) )
        #print( "HOSTS:     "+str( hosts ) )
        #print( "NETWORK:   "+Integer2IP( network ) )
        #print( "BROADCAST: "+Integer2IP( broadcast ) )
        
        # Set up an ARP sniffer to capture packets
        if VERBOSE: log.debug( "Starting Sniffer..." )
        self.sniffer = AsyncSniffer(filter="arp", prn=arp_handler)
        self.sniffer.start()
        
        if VERBOSE: log.debug( "Starting Scanner..." )
        try:
            while Running:
                # Loop through IP addresses (Ignoring Network and Broadcast Addresses)
                if VERBOSE: log.debug( "** Sending ARP Packets to subnet..." )
                #print( "* INTERFACE: "+settings.interface )
                for ip_int in range( network+1, broadcast ):
                    ip_str = Integer2IP( ip_int )
                    #print( ip_str )
                    packet = Ether( dst="ff:ff:ff:ff:ff:ff" ) / ARP( pdst=ip_str )
                    srp1( packet, iface=settings.interface, timeout=0.1, verbose=False )
                    # We do not need the answer (if any) because the sniffer is more reliable.
                    #if not Running: continue
                ## REAPER:
                # Loop through devices to identify expiration
                if VERBOSE: log.debug( "Checking device timeout..." )
                #now = time.time()
                for mac in list(devices.keys()):
                    #age = now - devices[mac]['last']
                    #print( mac, devices[mac]["ip"], devices[mac]["hostname"], devices[mac]['state'], age ) 
                    # Device status

                    # Don't do anything if online
                    #if devices[mac]['state']=='up': continue
                    # Increse counter
                    devices[mac]['counter']+=1
                    # Do we REAP?
                    if settings.reaper>0 and devices[mac]['counter']>settings.reaper:
                        # Publish DELETE event
                        mqtt_publish_event( "DELETE", mac, ip, hostname )
                        # Delete MQTT retained message
                        mqtt.publish( settings.topic+"/"+mac, "", qos=0, retain=True )
                        # Remove from device list
                        devices.pop( mac )
                    # Do we timeout?
                    elif devices[mac]['counter']>=settings.timeout:
                        #print( mac + " down")
                        if devices[mac]["timeout"]==True: return
                        # Update device
                        devices[mac]["timeout"]=True
                        devices[mac]['state']='down'
                        # Publish OFFLINE event
                        mqtt_publish_event( "OFFLINE", mac, devices[mac]['ip'], devices[mac]['hostname'] )
                        # UPdate MQTT
                        mqtt_publish_device( devices[mac] )
                    #else:
                        #print( mac+"  "+devices[mac]['ip']+"  "+str(devices[mac]['counter'])+"  "+devices[mac]['hostname'] )
                    #if not Running: continue
                if VERBOSE: log.debug( "Waiting for "+str(SCAN_DELAY)+" seconds" )
                time.sleep( SCAN_DELAY )
        except Exception as e:
            logging.exception(e)
            Running = False
        except KeyboardInterrupt:
            print( "User aborted" )
            Running = False
            
        if VERBOSE: log.debug( "Stopping Sniffer..." )
        self.sniffer.stop()
        
# Launcher
if __name__ == "__main__":

    # Load configuration
    settings.load()
    ## Attempt to create a default file
    settings.create(True)
    #settings.dump()

    if settings.verbose==1: VERBOSE=True
    if VERBOSE: log.debug( "STARTING HOMESCAN" )
    
    #print( "IP:   "+localAddress( settings.interface ) )
    #print( "MASK: "+localMask( settings.interface ) )

    # Connect to MQTT Broker
    if VERBOSE: log.debug( "* Connecting to MQTT Broker" )
    if VERBOSE: log.debug( ": BROKER:    "+settings.broker+":"+str(settings.port) )
    clientid=socket.gethostname()+"_"+os.path.basename(__file__)
    if VERBOSE: log.debug( ": CLIENT ID: "+clientid )
    mqtt = pahomqtt.Client( client_id=clientid, clean_session=True )
    if not settings.username=='':
        mqtt.username_pw_set( username=settings.username, password=settings.password )
        if VERBOSE: log.debug( ": AUTH:      "+settings.username+" | "+settings.password )
    mqtt.on_connect = mqtt_on_connect
    mqtt.on_disconnect = mqtt_on_disconnect
    mqtt.on_message = mqtt_on_message
    
    # Set Last Will and Testament
    if VERBOSE: log.debug( "* Setting LWT" )
    lwt = json.dumps( {"state":settings.offline}, default=str )
    mqtt.will_set( settings.state, lwt, qos=1, retain=True )
    
    # Connect to MQTT
    try:
        mqtt.connect( settings.broker, settings.port, 60 )
        #while not mqtt.connected_flag: #wait in loop
        #    time.sleep(1)
    except Exception as e:
        if VERBOSE: log.debug( "* Failed to connect to MQTT" )
        if VERBOSE: log.debug( "* Broker: "+settings.broker+":"+str(settings.port) )
        if VERBOSE: log.debug( str(e) )
        logging.exception(e)
        if settings.username=='':
            if VERBOSE: log.debug( "* Auth: Anonymous" )
        else:
            if VERBOSE: log.debug( "* Auth: "+settings.username )
        sys.exit(1)
        
    # Start Listening
    try:
        mqtt.loop_start()
        main=HomeScan()
        main.run()
    except Exception as e:
        #traceback.print_exc(file=sys.stdout)
        logging.exception(e)
        #client.publish( settings.state, json.dumps( {"state":"Failed"}, default=str ), qos=0, retain=True )
        #mqtt_publish_state( "Failed" )
        mqtt.loop_stop()
        sys.exit(1)
    except KeyboardInterrupt:
        if VERBOSE: print( "User aborted" )
        #client.publish( settings.state, json.dumps( {"state":"Aborted"}, default=str ), qos=0, retain=True )
        #mqtt_publish_state( "Aborted" )
        mqtt.loop_stop()
        sys.exit(1)
