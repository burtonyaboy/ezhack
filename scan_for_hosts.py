import subprocess

def find_hosts(interface='eth0'):
	ifconfig = subprocess.getoutput('ifconfig ' + interface + ' | grep  " inet "')
	ip_addr = ifconfig.split()[1]
	netmask = ifconfig.split()[3]
	network = '.'.join(ip_addr.split('.')[0:3] + ['0-255'])
	print(network)

def main():
	find_hosts()
	exit(0)

if __name__ == '__main__':
	main()