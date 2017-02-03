from subprocess import Popen, call, PIPE
import os
# from scapy import *
# from time import sleep
import re
import netifaces


devices = netifaces.interfaces()
DN = open(os.devnull, 'w')

def getAdapter(adpt=[]):
	# adpt = []

	patternwifi = '^B|^wl'


	print("Available Wi-Fi Adapter ready to use")
	print("ID | Wifi Adapter : ")
	print("====================================")
	for listWifi in devices:
		if re.match(patternwifi, listWifi, re.IGNORECASE):
			if listWifi not in adpt:
				adpt.append(listWifi)
				countList = len(adpt)
				print(" %s | %s " % (countList, listWifi))
				# print(type(countList))

	print("------------------------------------")

	select = int(input("Select {id} wifi adapter to use : "))

	for i in range(countList):
		choice = select-1
		if choice == i:
			setwifi = adpt[i]

	return setwifi

def enable_monitoring(get_iface='', mon_iface=[]):
	get_iface = getAdapter() # set wifi device to start airmon-ng
	
	disable_monitoring()

	setMonitoring = call(['airmon-ng', 'start', get_iface], stdout=DN, stderr=DN) # start airmon-ng with get_iface
	
	proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN) # run iwconfig commands

	# mon_iface = [] # list monitoring iface
	iwlist = proc.communicate()[0].split(b'\n') # identification proc.communicaate()[0].split('\n') to iwlist
	# keyMon = '^mon'

	for listMon in iwlist: # create list of Monitoring iface from iwlist
		if len(listMon) == 0: continue # if list of Monitoring iface 0 continue
		# b'\x0E'
		if (listMon[0]) != b' '[0]: # if list of Monitoring iface Doesn't start with space
			get_iface = listMon[:listMon.find(b' ')] # set wifi iface for monitoring
			# print(listMon.find())
			if listMon.find(b'Mode:Monitor') != -1:
				mon_iface.append(get_iface)
				# countMoniface = len(mon_iface)
				os.system("clear")
				print("Monitoring device ready on %s..." % get_iface.decode('utf-8'))
				# print(" %s | %s " % (countMoniface, get_iface))
				setMonIface = get_iface.decode('utf-8')

	return setMonIface

def disable_monitoring(get_iface=''):

	proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN) # run iwconfig commands
	iwlist = proc.communicate()[0].split(b'\n') # identification proc.communicate()[0].split('\n') to iwlist

	for listMon in iwlist: # create list of Monitoring iface from iwlist
		if len(listMon) == 0: continue # if list of Monitoring iface 0 continue
		if (listMon[0]) != b' '[0]: # if list of Monitoring iface Doesn't start with space
			get_iface = listMon[:listMon.find(b' ')] # set wifi iface for monitoring
			# print(listMon.find())
			if listMon.find(b'Mode:Monitor') != -1:
				# print(get_iface)
				print('Stoping all device monitoring : %s' % get_iface.decode('utf-8'))
				call(['airmon-ng', 'stop', get_iface.decode('utf-8')], stdout=DN, stderr=DN)
				print("Enabling device %s for monitoring" % get_iface.decode('utf-8'))
	return get_iface

# if __name__ == '__main__':
# 	enable_monitoring()
