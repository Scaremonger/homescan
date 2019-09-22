#!/usr/bin/python

## HOMESCAN: Network ARP Scan and Sniff
## (c) Copyright Si Dunford, Aug 2019
VER='1.1.0'

# Imports
from scapy.all import *
import socket, fcntl
import struct, traceback
import time
import paho.mqtt.client as pahomqtt
import json
import logging
from datetime import datetime
from lib.settings import settings
from lib.shared import *
from lib.wol import wakeonlan

# LOGGING
log = logging.getLogger( "homescan" )
handler = logging.FileHandler( 'homescan.log' )
formatter = logging.Formatter( '%(asctime)s %(levelname)s %(message)s' )
handler.setFormatter(formatter)
log.setLevel(logging.DEBUG)     # USE THIS DURING DEVELOPMENT
#log.setLevel(logging.INFO)     # USE THIS AFTER PUBLICATION
log.addHandler(handler)

SCAN_DELAY = 60 # Wait 60 seconds before starting next SCAN/REAP

# Debugging variables
VERBOSE    = 0  # By default, don't do verbose logging
MSG_INFO   = 0
MSG_ERROR  = 1

# Device list
devices = {}
address = {}
Running = True

# System state
isStarted = False

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
    #show( "arp_handler()" )
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
    #show( "--> arp_handler()" )
    
# MAC Address Sniffer Results
def mac_found( mac, ip, hostname, rtt ):
    #show( "mac_found()" )
    # Check if in list
    if mac in devices:
        # MAC address is already known
        device = devices[mac]
        # Reset Timeout counter to zero
        device["counter"]=0
        device["rtt"]=rtt
        # If device status up, re-publish it so that RTT is included
        if device['state']=="up":
            # Update MQTT
            mqtt_publish_device( device )
            if device['sleep']==True:
                mqtt_publish_event( settings.wake_msg, mac, ip, hostname ) 
        elif device['state']=="down":
        #elif device['state']=="down" or device['state']=="timeout":
            # Set State to online
            device['state']="up"
            # Update MQTT
            mqtt_publish_device( device )
            # Send ONLINE event
            mqtt_publish_event( settings.online_msg, mac, ip, hostname )          
        else:
            # State= unknown, or invalid
            # Set State to online
            device['state']="up"
            # Update MQTT (Only if not already up)
            #if not device['prestate']=='up':
            mqtt_publish_device( device )
            #device['prestate']=='up'
            # Do not send an event
            
        device['sleep']=False
        # Check for changes in IP adress and Hostname
        if not device["ip"]==ip:    # Device IP address has changed (Probably DHCP)
            # Send CHANGE event
            mqtt_publish_event( settings.updated_msg, mac, ip, hostname, "Previously "+device["ip"] )
            # Update device
            device["ip"]=ip
            # Update MQTT
            mqtt_publish_device( device )
        if not devices[mac]["hostname"]==hostname:  # Hostname changed!
            # Send CHANGE event
            mqtt_publish_event( settings.updated_msg, mac, ip, hostname, "Previously "+device["hostname"] )
            # Update device
            device["hostname"]=hostname
            # Update MQTT
            mqtt_publish_device( device )
    else:
        # MAC address is not previously known
        device = {"mac":mac, "ip":ip, "hostname":hostname, "state":"up", "counter":0, "rtt":rtt }
        # Add to Device list
        devices[mac]= device
        device['sleep']=False
        # Publish device into MQTT
        mqtt_publish_device( device )
        # Raise an ADDED event
        mqtt_publish_event( settings.added_msg, mac, ip, hostname )
    #show( "--> mac_found()" )

# MQTT connection
def mqtt_on_connect( client, userdata, flags, rc ):
    #global connected
    #show( "on_connect()" )
    client.connected_flag=True
#    if not isStarted:
#        message = { "event":"Start", "info":"Homescan Started" }
#        msg = json.dumps( message, default=str )
#        mqtt.publish( settings.events, msg, qos=0 )
#        isStarted = True
    if rc==0 :
        show( "MQTT connected")
        # Subscribe on connect so that subscriptions will recover disconnect
        client.subscribe(settings.topic+"/#")
        show( "Subscribed to '"+settings.topic+"/#'")
        # Set Application state to online
        mqtt_publish_state( settings.online_msg )
    else:
        show( "MQTT connection failed: ["+str(rc)+"] "+mqtt_errstr(rc), MSG_ERROR )
    #show( "--> on_connect" )
    
def mqtt_on_disconnect( client, userdata, rc ):
    #show( "on_disconnect()" )
    show( "MQTT disconnected: ["+str(rc)+"] "+mqtt_errstr(rc), MSG_ERROR ) 
    #show( "--> on_disconnect" )    

def mqtt_on_message( client, userdata, msg ):
    #show( "on_message()" )
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
            #device['prestate']=data["state"] if "state" in data else "unknown"
            device['state']=data["state"] if "state" in data else "down"
            #device['state']="unknown"
            # Other variables.
            device['counter']=0
            device['rtt']="-1"
            device['sleep']=False
            # Publish a "loaded" event for this device
            #mqtt_publish_event( "LOADED", device['mac'], device['ip'], device['hostname'] )
            devices[device['mac']]=device
        # We don't bother with non-retained messages here
        # (These will be published by ourself anyway)
    except Exception as e:
        show( "EXCEPTION", MSG_ERROR )
        show( str(e), MSG_ERROR )
        ##if VERBOSE: print( "** Something went wrong!" )
        #if VERBOSE: log.debug( str(e) )
        #if VERBOSE: traceback.print_exc(file=sys.stdout)
        #log.error("on_message error", exc_info=True)
        #log.exception(e)
        #log.emit()
    #show( "--> on_message" )    

# Publish a device status
def mqtt_publish_device( device ):
    #show( "mqtt_publish_device()" )
    data = { "mac":device['mac'], "ip":device['ip'], "hostname":device['hostname'], "state":device['state'], "rtt":device['rtt'] }
    msg = json.dumps( data, default=str )
    mqtt.publish( settings.topic+"/"+device['mac'], msg, qos=0, retain=True )
    #show( "--> mqtt_publish_device" )    

# Publish an event
# Added datetime in V1.0.6
def mqtt_publish_event( event, mac, ip, hostname, info='' ):
    #show( "mqtt_publish_event()" )
    show( "--> "+event )
    now = datetime.now()
    when = now.strftime("%Y%m%d, %H:%M:%S")
    message = { "datetime":when, "event":event, "mac":mac, "ip":ip, "hostname":hostname, "info":info }
    msg = json.dumps( message, default=str )
    mqtt.publish( settings.events, msg, qos=0 )
    #show( "-->mqtt_publish_event()" )

# Publish application state
# Datetime and Version added in V1.0.6
def mqtt_publish_state( state ):
    show( "mqtt_publish_state()" )
    #client.publish( settings.state, json.dumps( {"state":settings.online}, default=str ), qos=0, retain=True )
    now = datetime.now()
    when = now.strftime("%Y%m%d, %H:%M:%S")
    message = { "datetime":when, "state":state, "version":VER }
    msg = json.dumps( message, default=str )
    mqtt.publish( settings.state, msg, qos=0, retain=True )
    show( "-->mqtt_publish_state()" )
    
class HomeScan():
        
    def run( self ):
        global Running
        show( "HomeScan.run()" )

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
        show( "Starting Sniffer..." )
        self.sniffer = AsyncSniffer(filter="arp", prn=arp_handler)
        self.sniffer.start()
        
        show( "Starting Scanner..." )
        
        try:
            while Running:
                # Loop through IP addresses (Ignoring Network and Broadcast Addresses)
                show( "** Sending ARP Packets to subnet..." )
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
                show( "Checking device timeout..." )
                #now = time.time()
                for mac in list(devices.keys()):
                    #age = now - devices[mac]['last']
                    #print( mac, devices[mac]["hostname"], devices[mac]['state'], devices[mac]['counter'] ) 
                    #state = devices[mac]['state'] + "/" + "SLEEP" if devices[mac]['sleep']==True
                    show( mac+", "+devices[mac]['state']+", "+str(devices[mac]['counter'])+",("+str(devices[mac]['sleep'])+"), "+devices[mac]["hostname"] )
                    if devices[mac]["state"]=="up": 
                        if devices[mac]['sleep']==True:
                            if devices[mac]['counter']>=settings.offline:
                                devices[mac]['state']='down'
                                # Update MQTT
                                mqtt_publish_event( settings.offline_msg, mac, devices[mac]['ip'], devices[mac]['hostname'] )
                                mqtt_publish_device( devices[mac] )
                            else:
                                # Attempt to wake up device!
                                show( "--> Sending Wake-On-LAN" )
                                wakeonlan( mac, devices[mac]['ip'] )
                        else:
                            if devices[mac]['counter']>=settings.timeout:
                                devices[mac]['sleep']=True
                                # Update MQTT
                                mqtt_publish_event( settings.sleep_msg, mac, devices[mac]['ip'], devices[mac]['hostname'] )
                                #mqtt_publish_device( devices[mac] )
                    elif devices[mac]["state"]=="down":
                        if settings.reaper>0 and devices[mac]['counter']>=settings.reaper:
                            #show( "--> Reaping..." )
                            # Publish DELETE event
                            mqtt_publish_event( settings.leave_msg, mac, ip, hostname )
                            # Delete MQTT retained message
                            mqtt.publish( settings.topic+"/"+mac, "", qos=0, retain=True )
                            # Remove from device list
                            devices.pop( mac )
                    else:
                        # Not sure how it would get here!
                        # Unknown state, mark as down.
                        devices[mac]['state']='down'
                        
                    # Increse counter
                    devices[mac]['counter']+=1
                    
                show( "Waiting for "+str(SCAN_DELAY)+" seconds" )
                time.sleep( SCAN_DELAY )
        except Exception as e:
            show( "EXCEPTION", MSG_ERROR )
            show( str(e), MSG_ERROR )
            #log.error("Scan failure", exc_info=True)
            #log.exception(e)
            #log.emit()
            Running = False
        except KeyboardInterrupt:
            show( "User aborted" )
            Running = False
            
        show( "Stopping Sniffer..." )
        self.sniffer.stop()
        show( "--> HomeScan.run()" )

# Output a message to the logs or console depending on value of
# settings.verbose
def show( message, level=MSG_INFO ):
    state = VERBOSE
    # Errors will be reported regardless of VERBOSE setting
    if state==0 and level==MSG_ERROR: state=1
    
    # Verbose output is optional
    if state==0: 
        return
    elif state==1:  # LOGGING
        if level==MSG_INFO:
            log.info( message )
        else:
            log.error( message, exc_info=True ) 
    else:
        if level==MSG_INFO:
            print( "! "+message )
        else:
            print( "** "+message+" **" )
            traceback.print_exc(file=sys.stdout)

# Launcher
if __name__ == "__main__":
    show( "__main__" )

    # Load configuration
    settings.load()
    ## Attempt to create a default file
    settings.create(True)
    #settings.dump()

    VERBOSE = settings.verbose
    show( "STARTING HOMESCAN" )
    
    #print( "IP:   "+localAddress( settings.interface ) )
    #print( "MASK: "+localMask( settings.interface ) )

    # Connect to MQTT Broker
    show( "* Connecting to MQTT Broker" )
    show( ": BROKER:    "+settings.broker+":"+str(settings.port) )
    clientid=socket.gethostname()+"_"+os.path.basename(__file__)
    show( ": CLIENT ID: "+clientid )
    mqtt = pahomqtt.Client( client_id=clientid, clean_session=True )
    if not settings.username=='':
        mqtt.username_pw_set( username=settings.username, password=settings.password )
        show( ": AUTH:      "+settings.username+" | "+settings.password )
    mqtt.on_connect = mqtt_on_connect
    mqtt.on_disconnect = mqtt_on_disconnect
    mqtt.on_message = mqtt_on_message
    
    #print( "TIMEOUT: "+str(settings.timeout) )
    #print( "OFFLINE: "+str(settings.offline) )
    #print( "REAPER:  "+str(settings.reaper) )
    # Application starting
    #mqtt_publish_event( "STARTING", mac, devices[mac]['ip'], devices[mac]['hostname'] )
    
    # Set Last Will and Testament
    show( "* Setting LWT" )
    message = { "datetime":"", "state":settings.offline_msg, "version":VER }
    lwt = json.dumps( message, default=str )
    mqtt.will_set( settings.state, lwt, qos=1, retain=True )
    
    # Connect to MQTT
    mqtt.connected_flag = False
    #while not mqtt.connected_flag:
    show( "Connecting to MQTT..." )
    try:
        mqtt.connect( settings.broker, settings.port, 60 )
    #    while not mqtt.connected_flag: #wait in loop
    #        time.sleep(1)
    #    show( " Connected")
    #    #connected = True
    #except TimeoutError:
    #    show( "Timout error attempting to connect", MSG_ERROR )
    #    show( "Waiting 15 seconds before retry" )
    #    time.sleep( 15 )
    except Exception as e:
        show( "EXCEPTION", MSG_ERROR )
        show( str(e), MSG_ERROR )
        #if VERBOSE: log.debug( "* Failed to connect to MQTT" )
        #if VERBOSE: log.debug( "* Broker: "+settings.broker+":"+str(settings.port) )
        #if VERBOSE: log.debug( str(e) )
        #log.error("Fatal error while connect", exc_info=True)
        #log.exception(e)
        #log.emit()
        #if settings.username=='':
        #    if VERBOSE: log.debug( "* Auth: Anonymous" )
        #else:
        #    if VERBOSE: log.debug( "* Auth: "+settings.username )
        sys.exit(1)
    
    # Start Listening
    show( "Starting to Listen..." )
    try:
        mqtt.loop_start()
        main=HomeScan()
        main.run()
    except Exception as e:
        show( "EXCEPTION", MSG_ERROR )
        show( str(e), MSG_ERROR )
        #traceback.print_exc(file=sys.stdout)
        #log.error("Fatal error while listen", exc_info=True)
        #log.exception(e)
        #log.emit()
        #client.publish( settings.state, json.dumps( {"state":"Failed"}, default=str ), qos=0, retain=True )
        #mqtt_publish_state( "Failed" )
        mqtt.loop_stop()
        sys.exit(1)
    except KeyboardInterrupt:
        show( "User aborted" )
        #client.publish( settings.state, json.dumps( {"state":"Aborted"}, default=str ), qos=0, retain=True )
        #mqtt_publish_state( "Aborted" )
        mqtt.loop_stop()
        sys.exit(1)
    show( "--> __main__" )
