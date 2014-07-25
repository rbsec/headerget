headerget
=========

Get version headers from a list of websites. Boring headers are ignored, so only version headers (or unusual headers) are displayed.

Also displays hosts with missing security headers, or with insecure headers.

Site with identical headers are merged in the output.

Target file can be Nmap or servicescan XML output (use -sV so that http(s) servers on non-standard ports are detected).

Otherwise target is assumed to be plain text, with one host per line (protocol is optional, http assumed if none given).

Usage
=====
$ headerget.py \<targetfile or domain\>
