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
import traceback
from xml.dom import minidom
import OpenSSL

class col:
    if sys.stdout.isatty() and platform.system() != "Windows":
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        brown = '\033[33m'
        end = '\033[0m'
    else:   # Colours mess up redirected output, disable them
        green = ""
        blue = ""
        red = ""
        brown = ""
        end = ""


# Parse Nmap XML file
def xmlparse_nmap(xmldoc):
    hostlist = xmldoc.getElementsByTagName("host")
    for hostNode in hostlist :
        addressNode = hostNode.getElementsByTagName("address")
        host = addressNode[0].attributes["addr"].value
        ports = hostNode.getElementsByTagName("ports")
        try:
            portlist = ports[0].getElementsByTagName("port")
        except:
            continue
        for portNode in portlist:
            protocol = portNode.attributes["protocol"].value
            # Only interested in TCP
            if protocol != "tcp":
                continue
            port = portNode.attributes["portid"].value
            stateNode = portNode.getElementsByTagName("state")
            state = stateNode[0].attributes["state"].value
            serviceNode = portNode.getElementsByTagName("service")
            try:
                service = serviceNode[0].attributes["name"].value
            except:
                continue
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
        print(col.red + "Invalid XML file" + col.end)
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
            badheaders[target] += "x-content-type-options\n"
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
        m = re.search("max-age=(\d+)", headers["strict-transport-security"], re.IGNORECASE)
        if int(m.group(1)) < (60*60*24 * 30):     # Flag if less than 30 days
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
           print(col.blue + server + col.end)
       print(headers)


########
# Main #
########

# Supress warnings that we're not validating certificates
requests.packages.urllib3.disable_warnings()
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Get targets
targets = {}
try:
    arg = sys.argv[1]
except:
    print("\nUsage: $ " + sys.argv[0] + " <targetfile or domain>\n")
    sys.exit(1)

if arg == "-h" or arg == "--help":
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
    boringheaders = []
    with open(path, "r") as f:
        lines = f.readlines()
        for line in lines:
            boringheaders.append(line.rstrip().lower())
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
    except requests.exceptions.RequestException:
        try:
            print("HEAD failed, trying GET")
            r = requests.get(target, timeout=2, verify=False)
        except Exception as e:
            continue
    except requests.exceptions.ReadTimeout:
        print(col.red + target + " timed out" + col.end)
        continue
    except requests.exceptions.ConnectTimeout:
        print(col.red + target + " timed out" + col.end)
        continue
    except requests.exceptions.SSLError:
        print(col.red + target + " SSL error" + col.end)
        continue
    except OpenSSL.SSL.ZeroReturnError:
        print(col.red + target + " empty response" + col.end)
        continue
    except KeyboardInterrupt:
        print("\n\nCaught KeyboardInterrupt, quitting...")
        print("Results so far:\n")
        break
    except:
        print(traceback.format_exc())
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
    print(col.green + 'Interesting Headers' + col.end)
    print_headers(sorted)

# Missing security headers
sorted = reverse_dict(missingsecurity)
if len(sorted) > 0:
    print('\n' + col.brown + 'Missing Security Headers' + col.end)
    print_headers(sorted)

# Bad security headers
sorted = reverse_dict(badheaders)
if len(sorted) > 0:
    print('\n' + col.red + 'Bad Security Headers' + col.end)
    print_headers(sorted)
