## HOMESCAN TOOLS: event viewer
## (c) Copyright Si Dunford, Aug 2019
## Version 1.0.0

# Imports
import os,sys
import socket 
import paho.mqtt.client as pahomqtt
import json
from lib.settings import settings
from lib.shared import *

# Columns to display in debug results
COLUMNS={ "event":8, "mac":17, "ip":15, "hostname":30, "info":30 }
               
# MQTT connection
def mqtt_on_connect( client, userdata, flags, rc ):
    if rc==0 :
        print( "* MQTT connected OK")
        # Subscribe on connect so that subscriptions will recover disconnect
        client.subscribe( settings.events )
    else:
        print( "* MQTT connection failed: ["+str(rc)+"] "+mqtt_errstr(rc) )
        
def mqtt_on_disconnect( client, userdata, rc ):
    print( "* MQTT disconnected: ["+str(rc)+"] "+mqtt_errstr(rc) )

def mqtt_on_message( client, userdata, msg ):
    # Print message as table 
    print( row( json.loads( msg.payload ), COLUMNS ).strip() )

# Launcher
if __name__ == "__main__":

    print( "HOMESCAN EVENT VIEWER" )
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
    mqtt = pahomqtt.Client( client_id=clientid, clean_session=False )
    if not settings.username=='':
        mqtt.username_pw_set( username=settings.username, password=settings.password )
        print( ": AUTH:      "+settings.username+" | "+settings.password )
    mqtt.on_connect = mqtt_on_connect
    mqtt.on_disconnect = mqtt_on_disconnect
    mqtt.on_message = mqtt_on_message
    
    # Print table heading
    print( row( {"event":"EVENT", "mac":"MAC ADDRESS", "ip":"IP ADDRESS", "hostname":"HOSTNAME", "info":"INFO" }, COLUMNS ))
    print( row( {"event":"", "mac":"", "ip":"", "hostname":"", "info":"" }, COLUMNS, "-" ))
 
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
        mqtt.loop_forever()
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
    except KeyboardInterrupt:
        print( "User aborted" )
        sys.exit(1)
