#!/usr/bin/env python2
#
# Take a list of websites and scan them for any version headers
# Common headers are ignored, so only version or interesting ones are shown
# Sites with the same headers are merged in the output
# Usage: $ ./headerget.py <targetfile>
# Target file can be nmap XML output (use service detection with XML)
# Otherwise target file can be plain text, with one target per line
#

import os
import platform
import requests
import sys
from xml.dom import minidom

# Parse the targets (xml)
def xmlparse ():
    xmldoc = minidom.parse(sys.argv[1])
    hostlist = xmldoc.getElementsByTagName("host") 
    for hostNode in hostlist :
        addressNode = hostNode.getElementsByTagName("address")
        host = addressNode[0].attributes["addr"].value
        ports = hostNode.getElementsByTagName("ports")
        portlist = ports[0].getElementsByTagName("port")
        for portNode in portlist:
            port = portNode.attributes["portid"].value
            stateNode = portNode.getElementsByTagName("state")
            state = stateNode[0].attributes["state"].value
            serviceNode = portNode.getElementsByTagName("service")
            service = serviceNode[0].attributes["name"].value
            try:
                tunnel = serviceNode[0].attributes["tunnel"].value
            except:
                tunnel = ""
            
            if state == "open" and service == "http" and port == "80" and tunnel == "":
                target = "http://" + host
            elif state == "open" and service == "http" and tunnel == "":
                target = "http://" + host + ":" + port
            elif state == "open" and service == "http" and port == "443" and tunnel == "ssl":
                target = "https://" + host
            elif state == "open" and service == "http" and tunnel == "ssl":
                target = "https://" + host + ":" + port
            # If we don't have service info, just catch http/https based on port
            elif state == "open" and port == "80":
                target = "http://" + host
            elif state == "open"  and port == 443:
                target = "https://" + host
            targets[target] = ""

# Parse targets (txt)
def txtparse():
    for line in lines:
        if not line.startswith('http'):
            line = "http://" + line
        targets[line.rstrip()] = ""

# Open target file
targets = {}
try:
    with open(sys.argv[1]) as f:
        lines = f.readlines()
except:
    print("\nUsage: $ " + sys.argv[0] + " <targetfile>\n")
    sys.exit(1)

# Parse the file based on extension
if sys.argv[1].endswith("xml"):
    xmlparse()
else:
    txtparse()

# Get boring headers
try:
    path = os.path.dirname(os.path.realpath(__file__)) + "/boringheaders.txt"
    boringheaders = open(path).read().splitlines()
except IOError:
    print("File boringheaders.txt not found")
    sys.exit(1)

# The main scan
for target in targets:
    if sys.stdout.isatty():
        sys.stdout.write(target + "                                        \r")
        sys.stdout.flush()
    try:
        # Timeout after 2 seconds, don't try and verify the SSL cert
        r = requests.head(target, timeout=2, verify=False)
    except KeyboardInterrupt:
        print("\n\nCaught KeyboardInterrupt, quitting...")
        print("Results so far:\n")
        break
    except:
        continue

    for header in r.headers:
        if header.lower() not in boringheaders:
            targets[target] += header + ": " + r.headers[header] + "\n"

# Get rid of any trailing characters on the TTY
if sys.stdout.isatty():
    sys.stdout.write("                                                         \r")
    sys.stdout.flush()

# Reverse the array and sort it by headers
sorted = {}
for k, v in targets.items ():
    if v not in sorted:
        sorted [v] = []
    sorted [v].append (k)

# Print output
for headers,servers in sorted.items():
   if not headers:
       continue
   for server in servers:
        if sys.stdout.isatty() and platform.system() != "Windows":
            print('\033[94m' + server + '\033[0m')
        else:
            print(server)
   print(headers)
