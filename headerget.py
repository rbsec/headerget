#!/usr/bin/env python2
#
# Take a list of websites and scan them for any version headers
# Common headers are ignored, so only version or interesting ones are shown
# Sites with the same headers are merged in the output
# Usage: $ ./headerget.py <targetfile or domain>
# Target file can be nmap or servicescan XML output (use service detection with XML)
# Otherwise target file can be plain text, with one target per line
# Missing or misconfigured security headers are also listed
#

import os
import platform
import re
import requests
import sys
from xml.dom import minidom


# Parse Nmap XML file
def xmlparse_nmap(xmldoc):
    hostlist = xmldoc.getElementsByTagName("host")
    for hostNode in hostlist :
        addressNode = hostNode.getElementsByTagName("address")
        host = addressNode[0].attributes["addr"].value
        ports = hostNode.getElementsByTagName("ports")
        portlist = ports[0].getElementsByTagName("port")
        for portNode in portlist:
            protocol = portNode.attributes["protocol"].value
            # Only interested in TCP
            if protocol != "tcp":
                continue
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

            try:
                targets[target] = ""
            except UnboundLocalError:
                pass

# Parse servicescan XML file
def xmlparse_servicescan(xmldoc):
    hostlist = xmldoc.getElementsByTagName("host")
    for hostNode in hostlist :
        host = hostNode.attributes["address"].value
        portlist = hostNode.getElementsByTagName("port")
        for portNode in portlist:
            protocol = portNode.attributes["protocol"].value
            # Only interested in TCP
            if protocol != "TCP":
                continue
            port = portNode.attributes["number"].value
            state = portNode.attributes["state"].value
            desc = portNode.attributes["description"].value
            if state == "open" and desc == "HTTP" and port == "80":
                target = "http://" + host
            elif state == "open" and (desc == "HTTP" or desc == "HTTP-ALT"):
                target = "http://" + host + ":" + port
            elif state == "open" and desc == "HTTPS" and port == "443":
                target = "https://" + host
            elif state == "open" and desc == "HTTPS":
                target = "https://" + host + ":" + port

            try:
                targets[target] = ""
            except UnboundLocalError:
                pass

# Parse targets (xml)
def xmlparse ():
    xmldoc = minidom.parse(sys.argv[1])
    if xmldoc.getElementsByTagName("nmaprun"):
        xmlparse_nmap(xmldoc)
    elif xmldoc.getElementsByTagName("servicescan"):
        xmlparse_servicescan(xmldoc)
    else:
        print("Invalid XML file")
        sys.exit(1)

# Parse targets (txt)
def txtparse():
    for line in lines:
        if not line.startswith('http'):
            line = "http://" + line
        targets[line.rstrip()] = ""

# Reverse a dictionary
def reverse_dict(dictionary):
    sorted = {}
    for k, v in dictionary.items ():
        if v:
            if v not in sorted:
                sorted [v] = []
            sorted [v].append (k)
    return sorted

# Truncate a string to 80 chars
def trunc(string):
    return (string[:75] + '[...]') if len(string) > 80 else string

# Check for missing/bad security headers
def check_security_headers(target, headers):
    # X-Frame-Options
    try:
        m = re.search("SAMEORIGIN|DENY", headers["x-frame-options"], re.IGNORECASE)
        if not m:
            badheaders[target] += "x-frame-options: " + trunc(headers["x-frame-options"]) +"\n"
    except Exception as e:
        missingsecurity[target] += "x-frame-options\n"

    # X-Content-Type-Options: nosniff
    try:
        m = re.search("nosniff", headers["x-content-type-options"], re.IGNORECASE)
        if not m:
            missingsecurity[target] += "x-content-type-options\n"
    except:
        missingsecurity[target] += "x-content-type-options\n"

    # X-XSS-Protection
    try:
        m = re.search("0", headers["x-xss-protection"], re.IGNORECASE)
        if m:
            badheaders[target] += "x-xss-protection: " + trunc(headers["x-xss-protection"]) + "\n"
    except:
        pass

    # Strict-Transport-Security (HSTS)
    try:
        m = re.search("1", headers["strict-transport-security"], re.IGNORECASE)
        if not m:
            badheaders[target] += "strict-transport-security: " + trunc(headers["strict-transport-security"]) +"\n"
    except:
        missingsecurity[target] += "strict-transport-security\n"

    # Access-Control-Allow-Origin (CORS)
    try:
        m = re.search("\*", headers["access-control-allow-origin"], re.IGNORECASE)
        if m:
            badheaders[target] += "access-control-allow-origin: " + trunc(headers["access-control-allow-origin"]) +"\n"
    except:
        pass

    # Content-Security-Policy
    if not ("content-security-policy" in headers or "x-content-security-policy" in headers or "x-webkit-csp" in headers):
        missingsecurity[target] += "content-security-policy\n"


# Print the headers
def print_headers(headerarray):
    for headers,servers in headerarray.items():
       if not headers:
           continue
       for server in servers:
            if sys.stdout.isatty() and platform.system() != "Windows":
                print('\033[94m' + server + '\033[0m')
            else:
                print(server)
       print(headers)


########
# Main #
########

# Get targets
targets = {}
try:
    arg = sys.argv[1]
except:
    print("\nUsage: $ " + sys.argv[0] + " <targetfile or domain>\n")
    sys.exit(1)
if arg.startswith("http"):
    targets[arg] = ""
else:
    try:
        with open(sys.argv[1]) as f:
            lines = f.readlines()
    except:
        print("\nCould not open file " + arg)
        sys.exit(1)

# Parse the targets file based on extension
    if sys.argv[1].endswith("xml"):
        xmlparse()
    else:
        txtparse()

# Get list of boring headers
try:
    path = os.path.dirname(os.path.realpath(__file__)) + "/boringheaders.txt"
    boringheaders = open(path).read().splitlines()
except IOError:
    print("File boringheaders.txt not found")
    sys.exit(1)


# Scan the servers
headersfound = targets.copy()
missingsecurity = targets.copy()
badheaders = targets.copy()
for target in headersfound:
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
            h = (r.headers[header][:75] + '[...]') if len(r.headers[header]) > 80 else r.headers[header]
            headersfound[target] += header + ": " + h + "\n"
    check_security_headers(target, r.headers)

# Get rid of any trailing characters on the TTY
if sys.stdout.isatty():
    sys.stdout.write("                                                         \r")
    sys.stdout.flush()


# Interesting Headers
sorted = reverse_dict(headersfound)
if len(sorted) > 0:
    print('\033[92mInteresting Headers\033[0m')
    print_headers(sorted)

# Missing security headers
sorted = reverse_dict(missingsecurity)
if len(sorted) > 0:
    print('\n\033[33mMissing Security Headers\033[0m')
    print_headers(sorted)

# Bad security headers
sorted = reverse_dict(badheaders)
if len(sorted) > 0:
    print('\n\033[91mBad Security Headers\033[0m')
    print_headers(sorted)
