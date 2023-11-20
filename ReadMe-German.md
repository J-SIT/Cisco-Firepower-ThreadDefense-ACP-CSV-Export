

<br>
<br>
<br>
<br>


<br> Da das regelmäßige Dokumentieren der geschalteten Firewall-Regelwerke in einem Cisco Firepower Management Center einiges an Zeit mit sich bringt, soll dieser Prozess, welcher regelmäßig bei verschiedenen Kunden stattfindet, automatisiert werden. So kann ein Prozess, bei dem eine Bestandsliste des Regelwerks mit den aktuell geschalteten Regeln abgeglichen werden kann, mehrere Stunden dauern.
<br>
<br> Durch eine Automatisierung des Prozesses lässt sich dieser stundenlange Aufwand auf ca. 5 Minuten vereinfachen.
Dazu wird ein Python Skript auf dem Jumphost des Kunden ausgeführt, welches Kontakt zur FMC aufnimmt und sich mittels der Administrator-Log-in-Daten einwählt. Durch eine Datenbankabfrage wird eine CSV-Datei generiert, welche einige grundlegende für uns relevanten Informationen bereithält.
Da jedoch hierfür Python installiert sein muss, was unter Umständen aus Sicherheitsgründen nicht sehr ratsam sein kann, kann auch dieser Prozess optimiert werden. Mittels des Python-Programmes pyInstaller lässt sich aus einem Skript, welches ein auf dem Host ausgeführtes und installiertes Python benötigt, eine Stand-Alone Microsoft Executable Datei erstellen, welche ebenfalls funktioniert, ohne eine Python Installation auf dem Host zu benötigen.
<br>
<br> Zwar ist eine Single-Executable-Datei wesentlich einfacher zu handhaben, jedoch kann es ebenfalls sinnvoll sein, ein „normales“ Programm, welches auf Unterverzeichnisse verweist, mit Binärdateien zu verwenden. Da hier vorwiegend bei KRITIS Kunden durch den integrierten Virenscanner die verwendeten Bibliotheken der Executable eingesehen werden kann. So kann bei einer eventuellen kompromittierten Bibliothek seitens des Virenschutzes noch gemeldet und interveniert werden.
Als zusätzliche Absicherungsmaßnahme kann die Executable-Datei auch mit einem Zertifikat von der internen CA ausgestattet werden.
<br>
<br> Das Skript, auf welches die Executable basiert, läuft unter der BSD 3-Clause „New“ or „Revised“ Lizenz. Dies bedeutet, dass das Skript auch in kommerziellen Bereichen eingesetzt werden kann.
Weitere Informationen zu dem Skript vom Originalentwickler:
<br> https://developer.cisco.com/codeexchange/github/repo/raghukul-cisco/csvExportFirepower/
<br>
<br> Das Skript an sich:

```py
import re
import getpass
import sys
import warnings
import requests
import time
import json
from fireREST import FMC
from netaddr import *
import ipaddress
import datetime

#Global Variable

globalRules = {}

def acpCSV(fmc, selection):
	print ("Inside ACP")
	for policy in selection:
		ac_policy = policy
		policyFile = open(ac_policy + ".csv", "w")
		rules = fmc.policy.accesspolicy.accessrule.get(policy)
		refRules = {}
		policyFile.write("#, name,sourceZones, destZones, sourceNetworks, destNetworks, sourcePorts,destPorts, URL, APP, VLAN, Action, Enable, ipsPolicy, variableSet, filePolicy, logBegin, logEnd, sendEventsToFMC, syslogConfig, TimeRangeObject, Comments\n")
		pos = 0
		for ele in rules:
			#print("##########################")
			pos = pos + 1
			
			#Atomic mandatory fields in policies
			
			try:
				ips = ele['ipsPolicy']['name']
			except KeyError:
				ips = "NULL"

			try:
				file = ele['filePolicy']['name']
			except KeyError:
				file = "NULL"

			try:
				variable = ele['variableSet']['name']
			except KeyError:
				variable = "NULL"

			try:
				fmcEvents = ele['sendEventsToFMC']
			except KeyError:
				fmcEvents = ele['sendEventsToFMC']

			try:
				begin = ele['logBegin']
			except KeyError:
				begin = "NULL"

			try:
				end = ele['logEnd']
			except KeyError:
				end = "NULL"

			try:
				syslog = ele['enableSyslog']
			except KeyError:
				syslog = "NULL"

			
			enable = ele['enabled']

			#TimeBased Objects

			if ("timeRangeObjects" in ele.keys()):
				for local in ele['timeRangeObjects']:
					trObj = local['name']
			else:
				trObj = "NULL"

			#Check for time Range ACL if present


			#Zones Extraction
			sZones = []
			dZones = []
			try:
				temp = ele['sourceZones']
				for key,value in temp.items():
					for local in value:
						sZones.append(local['name'])
			except KeyError:
				sZones.append("Any")

			try:
				temp = ele['destinationZones']
				for key,value in temp.items():
					for local in value:
						dZones.append(local['name'])
			except KeyError:
				dZones.append("Any")

			#Network Extraction
			sNetwork = []
			dNetwork = []

			try:
				temp = ele['sourceNetworks']
				for key, value in temp.items():
					if ('literals' in key):
						for local in value:
							sNetwork.append(local['value'])
					if ('objects' in key):
						for local in value:
							sNetwork.append(local['name'])
			except KeyError:
				sNetwork.append("Any")

			try:
				temp = ele['destinationNetworks']
				for key, value in temp.items():
					if ('literals' in key):
						for local in value:
							dNetwork.append(local['value'])
					if ('objects' in key):
						for local in value:
							dNetwork.append(local['name'])
			except KeyError:
				dNetwork.append("Any")	

			print (ele['name'], sNetwork, dNetwork)

			#Port Extraction
			sPort = []
			dPort = []

			try:
				temp = ele['sourcePorts']	
				for key, value in temp.items():
					for local in value:
						if ('PortLiteral' in local['type']):
							sPort.append(local['type'])
						else:
							sPort.append(local['name'])
			except KeyError:
				sPort.append("Any")

			try:
				temp = ele['destinationPorts']
				for key, value in temp.items():
					for local in value:
						if ('PortLiteral' in local['type']):
							dPort.append(local['port'])
						else:
							dPort.append(local['name'])
			except KeyError:
				dPort.append("Any")

			#Applications and URL

			app = []
			url = []

			try:
				temp =  (ele['urls'])
				for key,value in temp.items():

					if ("urlCategoriesWithReputation" in key):
						for local in value:
							url.append(local['category']['name'])
					if ("literals" in key):
						for local in value:
							url.append(local['url'])
					if ("objects" in key):
						for local in value:
							url.append(local['name'])
			except KeyError:
				url.append("Any")

			try:
				temp = ele['applications']
				for key, value in temp.items():
					for local in value:
						if ("tags" in local.keys()):
							item = local['tags']
							for ite in item:
								app.append(ite['name'])
						if ("Application" in local['type']):
							app.append(local['name'])
			except KeyError:
				app.append("Any")

			#VLAN Tags

			vlan = []

			try:
				temp = ele['vlanTags']
				for key, value in temp.items():
					for local in value:
						if ('VlanTagLiteral' in local['type']):
							vlan.append(local['startTag'])
						else:
							vlan.append(local['name'])
			except KeyError:
				vlan.append("Any")

			#Comment History

			comment = []

			try:
				temp = ele['commentHistoryList']
				comment.append(temp)
			except KeyError:
				comment.append("Not Applicable")

			# Write CSV Header
			
			refRules[pos] = [pos, ele['name'], sZones, dZones, sNetwork, dNetwork, sPort, dPort, url, app, vlan, ele['action'], enable, ips, variable,file,begin, end, fmcEvents, syslog,trObj,comment]

			print("Writing rule #{0} to CSV...".format(pos))
			policyFile.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13}, {14}, {15}, {16}, {17}, {18}, {19}, {20}, {21}\n".format(pos,ele['name'],';'.join(sZones), ';'.join(dZones),';'.join(sNetwork), ';'.join(dNetwork),';'.join(sPort), ';'.join(dPort), url, app, vlan, ele['action'],enable, ips, variable, file, begin, end, fmcEvents, syslog, trObj, comment))
			
			

		globalRules[policy] = refRules
		print("File is at: ./{0}.csv".format(ac_policy))
		policyFile.close()


def getInput():
	
	hostname = input("Enter the IP Address of the FMC: ")
	username = input("Enter the username for the FMC: ")
	password = getpass.getpass("Enter the password associated with the username entered: ")
	fmc = FMC(hostname=hostname, username=username, password=password, domain='Global')
	acPolicies = fmc.policy.accesspolicy.get()

	pol = {}

	print ("ACP available in global domain: ")
	for policy in acPolicies:
		pol[policy['name']] = policy['id']
		print ("\tName: ", policy['name'])

	acp = input("Enter the ACP Name (case sensitive) if you want specific ACP to export(multiple values should be comma seperated). By default all the ACP would be exported, press return for default behaviour: ")
	
	selection = []

	if (acp):
		temp = acp.split(",")
		for local in temp:
			local = local.replace(" ", "")
			selection.append(pol[local])
	else:
		for local in acPolicies:
			selection.append(local['id'])

	acpCSV(fmc, selection)

getInput()
```

<br>
<br> Um das Skript in eine Executable umzuwandeln, benötigt man auf seinem Computer zur Vorbereitung des Programmes Python 3.
Anschließend muss (auch ohne Administratorrechten möglich) folgende Abhängigkeiten auf dem PC installiert werden, mit folgenden Befehlen:

```py
pip install fireREST
```
```py
pip install netaddr
```
```py
pip install datetime
```
```py
pip install ipaddress
```
```py
pip install pyinstaller
```

<br>
<br> Anschließend navigiert man in den Ordner, in welchem das Skript.py abliegt. Dann kann mit folgendem Befehl eine Single-Executable erstellt werden:

```py
pyinstaller --onefile .\policyCSV.py
```

<br>
<br> Oder alternativ ein Programm, welches nicht alle Abhängigkeiten in einer Datei trägt und stattdessen mit Unterverzeichnissen arbeitet:

```py
pyinstaller .\policyCSV.py
```

<br>
<br> Dieses Programm ist nun grundlegend fertig und kann auf das Zielsystem übertragen werden. Auf diesem muss weder Python noch die oben per pip installierten Abhängigkeiten installiert werden, da diese durch den pyInstaller bereits mit in die Executable integriert wurden.
