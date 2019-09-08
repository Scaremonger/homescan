# Homescan
An ARP Presence detection system for the Home that publishes on MQTT.

Application publishes:
* Application state UP/DOWN
* ARRIVE, DELETE, ONLINE, OFFLINE and CHANGE events
* Device MAC/IP/Hostname/STATE and Round Trip Time

# Project State
4 SEP 2019, Version 1.0.0, BETA
- Tested on Linux Mint Mint 19.1
- Untested on Windows and Linux


# Dependencies:
* TBC

# Installation

First, create a virtual environemnt:

    sudo apt-get install python3-venv
    sudo python3 -m venv /opt/venv

Install Homescan:

    cd /opt
    sudo git clone https://github.com/Scaremonger/homescan

    
Test installation:

    cd /opt/homescan
    sudo /opt/venv/bin/python3 homescan-state.py

Notes:
* Python3
* configparser

Set up default configuration and test:

    cd /opt/homescan
    sudo python3 homescan.py

# Configuration
Run the homescan status test and make a note of the location of your configuration file:

    cd /opt/homescan
    sudo python3 homescan.py

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
    
# Run as a service
TODO

# Tools

## homescan_events.py
This script can be used to view all events published to the homescan/events topic.

## homescan_devices.py
This script can be used to view all devices published to the homescan/devices topic.

## homescan_status.py
This script can be used to display the state of the homescan application as reported on MQTT topic homescan/homescan_status

# Known Bugs
- Script should identify the correct IP/MASK/INTERFACE as default
- interface, subnet and mask should really be in [network] section
- script status is not retained!

