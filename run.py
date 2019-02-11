#/usr/bin/python3

import ezhack


host_folder = './hosts/'


def main():
	targets = [ezhack.Host(host,host + '_1') for host in ezhack.scan_for_hosts()]
	for host in targets:
		print(host)
		'''
		ezhack.scan_target(host)
		ezhack.lookup_exploit(host)
		ezhack.exploit(host)
		ezhack.post_exploit(host)
'''

if __name__ == "__main__":
	main()