import subprocess

def find_hosts(interface='eth0'):
	ifconfig = subprocess.getoutput(f'ifconfig {interface} | grep  " inet "')
	ip_addr = ifconfig.split()[1]
	netmask = ifconfig.split()[3]
	network = '.'.join(ip_addr.split('.')[0:3] + ['0-255'])
	hosts = subprocess.getoutput(f'nmap -n -sn {network} -oG - | awk' + ' "/Up$/{print $2}"').split()
	print(hosts)

def main():
	find_hosts()
	exit(0)

if __name__ == '__main__':
	main()
