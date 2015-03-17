#!/usr/bin/python
# Cross-Site Tracer by 1N3 v1.2
# https://crowdshield.com
#
# ABOUT: A quick and easy script to check remote web servers for Cross-Site Tracing. For more robust mass scanning, you can create a list of domains or IP addresses to iterate through by doing 'for a in `cat targets.txt`; do ./xsstracer.py $a 80; done;'
#
# USAGE: xsstracer.py <IP/host> <port>
#

import socket
import time
import sys, getopt

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def main(argv):
	argc = len(argv)

	if argc <= 2:
		print bcolors.OKBLUE + "+ -- --=[Cross-Site Tracer by 1N3 v20150224" + bcolors.ENDC
		print bcolors.OKBLUE + "+ -- --=[" + bcolors.UNDERLINE + "https://crowdshield.com" + bcolors.ENDC
        	print bcolors.OKBLUE + "+ -- --=[usage: %s <host> <port>" % (argv[0]) + bcolors.ENDC
        	sys.exit(0)

	target = argv[1] # SET TARGET
	port = argv[2] # SET PORT

	buffer1 = "TRACE / HTTP/1.1"
	buffer2 = "Test: <script>alert(1);</script>"
	buffer3 = "Host: " + target

	print ""
	print bcolors.OKBLUE + "+ -- --=[Cross-Site Tracer by 1N3 "
	print bcolors.OKBLUE + "+ -- --=[https://crowdshield.com"
	print bcolors.OKBLUE + "+ -- --=[Target: " + target + ":" + port 

	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	result=s.connect_ex((target,int(port)))
	s.settimeout(1.0)
	#conn,addr = s.accept()
	#conn.settimeout(5.0)

	if result == 0:
		s.send(buffer1 + "\n")
		s.send(buffer2 + "\n")
		s.send(buffer3 + "\n\n")
		data = s.recv(1024)
		script = "alert"
		if script.lower() in data.lower():
			print bcolors.FAIL + "+ -- --=[Site vulnerable to XST!" + bcolors.ENDC
			print ""
			print bcolors.WARNING + data + bcolors.ENDC
		else:
			print bcolors.OKGREEN + "+ -- --=[Site not vulnerable to XST!"
			print ""
			print ""

	else:
		print bcolors.WARNING + "+ -- --=[Port is closed!" + bcolors.ENDC

	s.close()

main(sys.argv)
