#!/usr/bin/env python2
#
# Take a list of websites and scan them for any version headers
# Common headers are ignored, so only version or interesting ones are shown
# Sites with the same headers are merged in the output
# Usage: $ ./headerget.py <targetfile>
#

import os
import requests
import sys

# Open target file
targets = {}
try:
    with open(sys.argv[1]) as f:
        lines = f.readlines()
except:
    print("\nUsage: $ " + sys.argv[0] + " <targetfile>\n")
    sys.exit(1)

# Parse targets (txt)
for line in lines:
    if not line.startswith('http'):
        line = "http://" + line
    targets[line.rstrip()] = ""

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
        r = requests.head(target, timeout=2, verify=False)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, quitting...")
        sys.exit(1)
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
        print(server)
   print(headers)
