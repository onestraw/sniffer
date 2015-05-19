#port scan detector

##Introduction
--------

- build: gcc catcher.c -lpcap -o catcher
- run: sudo ./catcher
- ./catcher --help

		Usage: ./catcher [options]
		  -d device       Use 'device' as the network interface device
				  The first non-loopback interface is the default
		  -f flood        Assume a synflood attack occurred if more than
				  'flood' uncompleted connections are received
		  -h              A little help here
		  -i icmplimit    Assume we may be part of a smurf attack if more
				  than icmplimit ICMP ECHO REPLIES are seen
		  -m level        Monitor more than just our own host.
				  A level of 'subnet' watches all addresses in our
				  subnet and 'all' watches all addresses
		  -p portlimit    Logs a portscan alert if packets are received for
				  more than portlimit ports in the timeout period.
		  -r reporttype   If reporttype is dos, only Denial Of Service
				  attacks are reported.  If reporttype is scan
				  then only scanners are reported.  Everything is
				  reported by default.
		  -t timeout      Count packets and print potential attacks every
				  timeout seconds
		  -w webcount     Assume we are being portscanned if more than
				  webcount packets are received from port 80


##About
****   

- author: `geeksword`
- email: geeksword@163.com
- blog: http://onestraw.net
- reference: `watcher.c`
