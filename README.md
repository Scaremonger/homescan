# Homescan
An ARP Presence detection system for the Home that publishes on MQTT.
By default, it will attempt to connect to an open MQTT broker on the local system; this can be changed by editing the configuration file.

Join us on the Homescan channel on Discord at:
https://discord.gg/FhcKbr4

Homescan publishes the following information to MQTT:
* Hoemscan application state (UP/DOWN)
* ARRIVE, DELETE, ONLINE, OFFLINE and CHANGE events
* Device MAC/IP/Hostname/STATE and Round Trip Time

# Project State
BETA RELEASE
Platforms supported:
* Linux Mint Mint 19.1

Platforms untested:
* Raspabian
* Ubuntu
* Windows

# Dependencies:
* Paho MQTT

# Installation
This installation creates a virtual environment and adds dependedncies:

    sudo apt-get install python3-venv
    sudo python3 -m venv /opt/venv
    sudo /opt/venv/bin/python3 -m pip install paho-mqtt
    sudo /opt/venv/bin/python3 -m pip install scapy
    
    cd /opt
    sudo git clone https://github.com/Scaremonger/homescan

Test installation:

    cd /opt/homescan
    sudo /opt/venv/bin/python3 homescan-state.py

    (Press Ctrl-C to abort if required)
Homescan will attempt to connect to MQTT on the local system by default, but you should now configure the following options if required:
    
    broker
        This defaults to 127.0.0.1 and will need to be changed if you have
        it installed on another system
    port
        This is the default MQTT port of 1883
    username / password
        You need to set your username and password if you have added security to MQTT broker
    interface
        If your system interface is not called "eth0" your will need to change this.
        Please check the output of "ifconfig" for your system details.

TIP:
Open another terminal session for each of the tools provided with homescan:

    cd /opt/homescan
    sudo homescan-state.py
    
    cd /opt/homescan
    sudo homescan-devices.py

    cd /opt/homescan
    sudo homescan-events.py

Run as a service

    sudo cp /opt/homescan/bin/homescan.service /etc/systemd/system/
    sudo chmod u+rwx /etc/systemd/system/homescan.service
    sudo systemctl enable homescan
    sudo systemctl start homescan

# Configuration
Edit your configuration file:

    sudo nano /etc/homescan/homescan.ini
    (or use notepad++ in windows)
    
[homescan]
broker=
    This is the IP adress of your MQTT broker
    Default is 127.0.0.1
port=
    This is the port that your MQTT server is listening on
username=
    MQTT username. If blank or not specified it will login anonymously
password=
    MQTT password, Only used if username is set.

topic=
    The topic used to save device status
    Default is homescan/devices
events=
    The topic used to publish events
    Default is homescan/events
status=
    The topic used to publish script status
    (See also offline_message and online_message)
    Default is homescan/status

timeout=
    How often (in minutes) the script should timeout a device as OFFLINE
    Default: 3
reaper=
    How long (in minutes) before a device is deleted from the database
    (Time since device was last seen)
    When set to 0, the reaper will not function and records will never be deleted
    Default: 10080 (7 days)

offline_message=
    The message that is posted to STATUS topic when script is offline
    Default: DOWN
online_message=
    The message that is posted to STATUS topic when script is online
    Default: UP

interface=
    REQUIRED
    The name of the interface used for scanning
    Default: eth1
subnet=
    OPTIONAL
    The script will attempt to identify your address, but this can be used to override this behaviour
    The network address of your home (Can also be your IP address)
    Default: 192.168.1.0
mask=
    OPTIONAL
    The script will attempt to identify your address, but this can be used to override this behaviour
    The subnet mask of your network
    Default: 255.255.255.0
    
# Updating to latest version

    sudo service homescan stop
    cd /opt/homescan
    sudo git pull
    sudo service homescan start
    
# Tools

## homescan_events.py
This script can be used to view all events published to the homescan/events topic.

## homescan_devices.py
This script can be used to view all devices published to the homescan/devices topic.

## homescan_status.py
This script can be used to display the state of the homescan application as reported on MQTT topic homescan/homescan_status

# Errors:
OSError: [Errno 19] No such device

Check that "interface=" is set to the correct interface for your system. 
Run "ifconfig" (linux) or "ipconfig" (windows) to check the interfaces on your system.
Update configuration file

