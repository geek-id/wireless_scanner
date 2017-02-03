from iface_mon import *
from scapy.all import *
from time import sleep
import re, subprocess, os, sys, signal, random
# from multiprocessing import Process
conf.verb = 0

interface = enable_monitoring()
apscan = {}

def sniffAP(p):

	# if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and not apscan.has_key(p[Dot11].addr3)):
	if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and p[Dot11].addr3 not in apscan ) :

		ssid = p[Dot11Elt].info
		bssid = p[Dot11].addr3
		channel = int(ord(p[Dot11Elt:3].info))
		capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

		if re.search("privacy", capability):
			enc = 'Y'
		else:
			enc = 'N'
		apscan[p[Dot11].addr3] = enc

		print("%02d %s   %s  %s" % (int(channel), enc, bssid, ssid.decode('utf-8')))

# def channel_hopper():
#     while True:
#         try:
#             channel = random.randrange(1,12)
#             os.system("iw dev %s set channel %d" % (interface, channel))
#             sleep(1)
#         except KeyboardInterrupt:
#             break

def signal_handler(signal, frame):
    # p.terminate()
    # p.join()

    print ("\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-")
    print ("Total APs found: %d" % len(apscan))
    print ("Encrypted APs  : %d" % len([ap for ap in apscan if apscan[ap] =='Y']))
    print ("Unencrypted APs: %d" % len([ap for ap in apscan if apscan[ap] =='N']))

    sys.exit(0)

if __name__ == "__main__":
    
    # Print the program header
    print ("-=-=-=-=-=-= wirelesScan.py =-=-=-=-=-=-")
    print ("CH ENC BSSID              SSID")

    # Start the channel hopper
    # p = Process(target = channel_hopper)
    # p.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    sniff(iface=interface,prn=sniffAP)