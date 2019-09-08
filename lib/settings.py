## HOMESCAN SETTINGS
## (c) Copyright Si Dunford, Aug 2019
## Version 1.0.0

# UNTESTED ON WINDOWS AND MAC

import configparser as configParser
import json
import sys
import os
import logging

APPNAME="homescan"
COMPANY="Scaremonger"

# LOGGING
log = logging.getLogger( APPNAME )

## This was improved after reviewing ActiveState/appdirs
## Thanks for assistance with "java"...
if sys.platform.startswith('java'):
    import platform
    os_name = platform.java_ver()[3][0]
    if os_name.startswith( 'Windows' ):
        system = 'win32'
    elif os_name.startswith( 'Mac' ):
        system = 'darwin'
    else:
        system = 'linux'
else:
    system = sys.platform

''' CONFIG PATH:
XP:	    %SystemDrive%\Documents and Settings\All Users\Application Data
Vista:	%SystemDrive%\ProgramData\MyCompany\MyApp
Win7:	%SystemDrive%\ProgramData\MyCompany\MyApp
Win10:	%SystemDrive%\ProgramData\MyCompany\MyApp
LINUX:  /etc/<APPNAME>
MACOS:  ~/Library/Application Support/<APPNAME>
'''
def config_path():    
    if system == "win32" or system=="win64":
        release = platform.release()
        # Options appear to be NT,2K,XP,Vista,7,10
        # ONly Vista al=ppears to store shared data in a different path
        if release == "XP":
            path = "%SystemDrive%/Documents/"
        else:
            path = "%SystemDrive%/ProgramData/"+COMPANY
        path = os.path.join(path, APPNAME)
    elif system == 'darwin':
        path = os.path.expanduser('~/Library/Application Support/')
        path = os.path.join(path, APPNAME)
    else:
        #path = os.getenv('XDG_DATA_HOME', os.path.expanduser("~/.local/share"))
        #path = os.path.join(path, APPNAME)
        path = "/etc/"+APPNAME
    if not path.endswith("/"):
        path+="/"
    return path

class Settings():
    
    def __init__( self ):
        self.filename = APPNAME+".ini"
        self.filepath = config_path()
        self.configfile = self.filepath + self.filename
        self.exists = os.path.isfile( self.configfile )
        self.config = configParser.ConfigParser()
        if not self.exists: 
            print( "*Config file does not exist")
            return
        with open( self.configfile ) as source:
            self.config.read( self.configfile )
        
    def create( self, verbose ):
        if self.exists:
            return
        # Create folder
        if not os.path.isdir( self.filepath ):
            #if verbose: print( "! Folder does not exist" )
            # Create the folder
            try:
                os.makedirs( self.filepath )
                if verbose: log.debug( ": Created folder "+self.filepath )
            except:
                if verbose: log.debug( "* Unable to create folder "+self.filepath )
                return
        # Create config file
        if not os.path.isfile( self.configfile ):
            self.save( )

    def load( self ):
        self.broker     = self.get( 'homescan', 'broker', '127.0.0.1' )
        self.port       = self.getint( 'homescan', 'port', 1883 )
        self.username   = self.get( 'homescan', 'username', '' )
        self.password   = self.get( 'homescan', 'password', '' )
        #self.interval   = self.getint( 'homescan', 'interval', 60 )
        #self.expiration = self.getint( 'homescan', 'expiration', 300 )
        #self.deletion   = self.getint( 'homescan', 'deletion', 604800 )
        self.timeout    = self.getint( 'homescan', 'timeout', 3 )  # minutes
        self.reaper     = self.getint( 'homescan', 'reaper', 10080 )  # minutes (7 days)
        self.topic      = self.get( 'homescan', 'topic', 'homescan/devices' )
        self.state      = self.get( 'homescan', 'state', 'homescan/state' )
        self.events     = self.get( 'homescan', 'events', 'homescan/events' )
        self.offline    = self.get( 'homescan', 'offline_message', 'DOWN' )
        self.online     = self.get( 'homescan', 'online_message', 'UP' )
        
        self.interface  = self.get( 'homescan', 'interface', 'eth1' )
        self.subnet     = self.get( 'homescan', 'subnet', '' )
        self.mask       = self.get( 'homescan', 'mask', '' )
        self.verbose    = self.getint( 'homescan', 'verbose', 0 ) 
        
        # Fix-up's
        self.topic = self.topic.rstrip('/')
        self.state = self.state.rstrip('/') 
        self.events = self.events.rstrip('/') 
        
    def dump( self ):
        for attr in dir(self):
            if type(getattr(self, attr))==str or type(getattr(self, attr))==int:
                print("  .%s = %r" % (attr, getattr(self, attr)))
                
    def get( self, section, key, default='' ):
        if not self.exists:
            return default
        if self.config.has_section( section ):
            return self.config[section].get( key, default )
        #print( "Cannot read "+section+"/"+key )
        return default

    def getint( self, section, key, default=0 ):
        if not self.exists:
            return default
        if self.config.has_section( section ):
            return self.config[section].getint( key, default )
        #print( "Cannot read "+section+"/"+key )
        return default

    def getfloat( self, section, key, default=0.0 ):
        if not self.exists:
            return default
        if self.config.has_section( section ):
            return self.config[section].getfloat( key, default )
        #print( "Cannot read "+section+"/"+key )
        return default

    def set( self, section, key, value ):
        value = str(value)
        if not self.config.has_section( section ):
            self.config.add_section( section )
        self.config.set( section, key, value )

    def save( self ):
        #print(".saving...")
        self.set( 'homescan', 'broker', self.broker )
        self.set( 'homescan', 'port', self.port )
        self.set( 'homescan', 'username', self.username )
        self.set( 'homescan', 'password', self.password )

        self.set( 'homescan', 'topic', self.topic )
        self.set( 'homescan', 'state', self.state )
        self.set( 'homescan', 'events', self.events )
        self.set( 'homescan', 'offline_message', self.offline )
        self.set( 'homescan', 'online_message', self.online )

        #self.set( 'homescan', 'interval', self.interval )
        #self.set( 'homescan', 'expiration', self.expiration )
        #self.set( 'homescan', 'deletion', self.deletion )
        self.set( 'homescan', 'timeout', self.timeout )
        self.set( 'homescan', 'reaper', self.reaper )
        
        self.set( 'homescan', 'interface', self.interface )
        self.set( 'homescan', 'subnet', self.subnet )
        self.set( 'homescan', 'mask', self.mask )

        self.set( 'homescan', 'verbose', self.verbose )
        try:
            with open( self.configfile, 'w') as configfile:
                self.config.write( configfile )
            log.debug( "* Created config file "+self.configfile )
        except:
            log.debug( "* Unable to save file "+self.configfile )
            
settings=Settings()

