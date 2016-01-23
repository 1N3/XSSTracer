#!/usr/bin/python
# Cross-Site Tracer v1.3 by 1N3
# https://crowdshield.com
#
# ABOUT: A python script to check remote web servers for Cross-Site Tracing, Cross-Frame Scripting/Clickjacking and Host Header Injection vulnerabilities. For more robust mass scanning, you can create a list of domains or IP addresses to iterate through by doing 'for a in `cat targets.txt`; do ./xsstracer.py $a 80; done;'
#
# USAGE: xsstracer.py <IP/host> <port>
#

import socket, time, sys, getopt, httplib

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
		print bcolors.OKBLUE + "	__  ______ _____ " + bcolors.ENDC
		print bcolors.OKBLUE + "	\ \/ / ___|_   _|" + bcolors.ENDC
		print bcolors.OKBLUE + "	 \  /\___ \ | |  " + bcolors.ENDC
		print bcolors.OKBLUE + "	 /  \ ___) || |  " + bcolors.ENDC
		print bcolors.OKBLUE + "	/_/\_|____/ |_|  " + bcolors.ENDC
		print ""
		print bcolors.OKBLUE + "+ -- --=[Cross-Site Tracer by 1N3 v1.3" + bcolors.ENDC
		print bcolors.OKBLUE + "+ -- --=[" + bcolors.UNDERLINE + "https://crowdshield.com" + bcolors.ENDC
        	print bcolors.OKBLUE + "+ -- --=[usage: %s <host> <port>" % (argv[0]) + bcolors.ENDC
        	sys.exit(0)

	target = argv[1] # SET TARGET
	port = argv[2] # SET PORT

	if port == 443:
		print "Using HTTPS"
		headers = {
			'User-Agent': 'XSS Tracer v1.3 by 1N3 @ https://crowdshield.com',
			'Content-Type': 'application/x-www-form-urlencoded',
		}

		conn = httplib.HTTPSConnection(host)
		conn.request("GET", "/", "", headers)
		response = conn.getresponse()
		data = response.read()

		print 'Response: ', response.status, response.reason
		print 'Data:'
		print data

	else:
		buffer1 = "TRACE / HTTP/1.1"
		buffer2 = "Test: <script>alert(1);</script>"
		buffer3 = "Host: " + target

		buffer4 = "GET / HTTP/1.1"

		print ""
		print bcolors.OKBLUE + "	__  ______ _____ " + bcolors.ENDC
		print bcolors.OKBLUE + "	\ \/ / ___|_   _|" + bcolors.ENDC
		print bcolors.OKBLUE + "	 \  /\___ \ | |  " + bcolors.ENDC
		print bcolors.OKBLUE + "	 /  \ ___) || |  " + bcolors.ENDC
		print bcolors.OKBLUE + "	/_/\_|____/ |_|  " + bcolors.ENDC
		print ""
		print bcolors.OKBLUE + "+ -- --=[Cross-Site Tracer v1.3 by 1N3 @ CrowdShield" + bcolors.ENDC
		print bcolors.OKBLUE + "+ -- --=[Target: " + target + ":" + port + bcolors.ENDC

		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result=s.connect_ex((target,int(port)))
		s.settimeout(1.0)

		if result == 0:
			s.send(buffer1 + "\n")
			s.send(buffer2 + "\n")
			s.send(buffer3 + "\n\n")
			data1 = s.recv(1024)
			s.close()

			script = "alert"
			xframe = "X-Frame-Options"
			#hsts = "Strict-Transport-Security"

			# TEST FOR XST
			if script.lower() in data1.lower():
				print bcolors.FAIL + "+ -- --=[Site vulnerable to Cross-Site Tracing!" + bcolors.ENDC

			else:
				print bcolors.OKGREEN + "+ -- --=[Site not vulnerable to Cross-Site Tracing!" + bcolors.ENDC

			# TEST FOR HOST HEADER INJECTION
			frame_inject = "crowdshield"
			buffer1 = "GET / HTTP/1.1"
			buffer2 = "Host: http://crowdshield.com"

			s3=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result=s3.connect_ex((target,int(port)))
			s3.settimeout(1.0)
			s3.send(buffer1 + "\n")
			s3.send(buffer2 + "\n\n")
			data3 = s3.recv(1024)
			s3.close()

			if frame_inject.lower() in data3.lower():
				print bcolors.FAIL + "+ -- --=[Site vulnerable to Host Header Injection!" + bcolors.ENDC

			else:
				print bcolors.OKGREEN + "+ -- --=[Site not vulnerable to Host Header Injection!" + bcolors.ENDC

			# TEST FOR CLICKJACKING AND CFS
			s2=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result=s2.connect_ex((target,int(port)))
			s2.settimeout(1.0)
			s2.send(buffer4 + "\n")
			s2.send(buffer3 + "\n\n")
			data2 = s2.recv(1024)
			s2.close()

			if xframe.lower() in data2.lower():
				print bcolors.OKGREEN + "+ -- --=[Site not vulnerable to Cross-Frame Scripting!" + bcolors.ENDC
				print bcolors.OKGREEN + "+ -- --=[Site not vulnerable to Clickjacking!" + bcolors.ENDC

			else:
				print bcolors.FAIL + "+ -- --=[Site vulnerable to Cross-Frame Scripting!" + bcolors.ENDC
				print bcolors.FAIL + "+ -- --=[Site vulnerable to Clickjacking!" + bcolors.ENDC
		
			# DISPLAY HEADERS
			print ""
			print bcolors.WARNING + data1 + bcolors.ENDC
			print bcolors.WARNING + data2 + bcolors.ENDC
			print ""
			print ""

		else:
			print bcolors.WARNING + "+ -- --=[Port is closed!" + bcolors.ENDC

main(sys.argv)

