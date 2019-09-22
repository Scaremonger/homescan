## HOMESCAN TOOLS: device state
## (c) Copyright Si Dunford, Aug 2019
## Version 1.1.0

# Imports
import os,sys,traceback,platform,subprocess
import time
import socket 
import paho.mqtt.client as pahomqtt
import json
from lib.settings import settings
from lib.shared import *

# Device list
devices = {}

# Columns to display in debug results
COLUMNS={ "mac":17, "ip":15, "state":8, "rtt":"8:R", "hostname":17 }
               
# MQTT connection
def mqtt_on_connect( client, userdata, flags, rc ):
    if rc==0 :
        print( "* MQTT connected OK")
        # Subscribe on connect so that subscriptions will recover disconnect
        client.subscribe(settings.topic+"/#")
    else:
        print( "* MQTT connection failed: ["+str(rc)+"] "+mqtt_errstr(rc) )
        
def mqtt_on_disconnect( client, userdata, rc ):
    print( "* MQTT disconnected: ["+str(rc)+"] "+mqtt_errstr(rc) )

def mqtt_on_message( client, userdata, msg ):
    # Print message as table 
    #print( row( json.loads( msg.payload ), COLUMNS ) )
    try:
        decoded=str(msg.payload.decode("utf-8","ignore"))
        #print( "TOPIC:   "+msg.topic )
        #print( "PAYLOAD: "+decoded )
        #if msg.retain==1:
        #print( "Loading "+decoded )
        #print( "* Retained:" )
        # Check if device is in our device list
        device = json.loads( decoded )
        if "mac" in device:
            mac = device["mac"]
            if not "rtt" in device: device['rtt']='-1'
            if not "state" in device: device['state']="Unknown"
            # Decimal align RTT
            rtt = float(device['rtt'])
            device['rtt']=f'{rtt:8.0f}'
            #device['rtt']=int(device['rtt'])
            if not mac in devices:
                devices[mac]=device
            else:
                devices[mac]=device
        #else:
        #    print( "Updating "+decoded )
            
    except Exception as e:
        print( "** on_message() exception **" )
        print( str(e) )
        traceback.print_exc(file=sys.stdout)
        
# Launcher
if __name__ == "__main__":

    print( "HOMESCAN DEVICE VIEWER" )
    print( "CONFIG PATH: " + settings.configfile )
    
    # Load configuration
    settings.load()
    ## Attempt to create a default file
    settings.create(True)
    #settings.dump()

    # Connect to MQTT Broker
    print( ": Connecting to MQTT Broker" )
    print( ": BROKER:    "+settings.broker+":"+str(settings.port) )
    clientid=socket.gethostname()+"_"+os.path.basename(__file__)
    print( ": CLIENT ID: "+clientid )
    mqtt = pahomqtt.Client( client_id=clientid, clean_session=True )
    if not settings.username=='':
        mqtt.username_pw_set( username=settings.username, password=settings.password )
        print( ": AUTH:      "+settings.username+" | "+settings.password )
    mqtt.on_connect = mqtt_on_connect
    mqtt.on_disconnect = mqtt_on_disconnect
    mqtt.on_message = mqtt_on_message
 
    # Connect to MQTT
    try:
        mqtt.connect( settings.broker, settings.port, 60 )
        #while not mqtt.connected_flag: #wait in loop
        #    time.sleep(1)
    except Exception:
        print( "* Failed to connect to MQTT" )
        print( "* Broker: "+settings.broker+":"+str(settings.port) )
        if settings.username=='':
            print( "* Auth: Anonymous" )
        else:
            print( "* Auth: "+settings.username )
        sys.exit(1)

    # Start Listening
    try:
        mqtt.loop_start()
        while True:
            # Clear the screen
            cls = "cls" if platform.system().lower()=="windows" else "clear"
            subprocess.call( cls )
            # Print table heading
            print( row( {"mac":"MAC ADDRESS", "ip":"IP ADDRESS", "state":"STATE", "rtt":"RTT (ms)", "hostname":"HOSTNAME" }, COLUMNS ))
            print( row( {"mac":"", "ip":"", "state":"", "rtt":"", "hostname":"" }, COLUMNS, "-" ))
            now = time.time()
            for mac in devices:
                device = devices[mac]
                #age = int( now - device['last'] )
                #device['age']=str(age)
                #print( mac )
                print( row( device, COLUMNS ).strip() )
            time.sleep( 5 )
    except Exception:
        traceback.print_exc(file=sys.stdout)
        mqtt.loop_stop()
        sys.exit(1)
    except KeyboardInterrupt:
        print( "User aborted" )
        mqtt.loop_stop()
        sys.exit(1)
