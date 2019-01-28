import subprocess

def find_hosts(interface='eth0'):
	ip_list = []
	ifconfig = subprocess.getoutput(f'ifconfig {interface} | grep  " inet "')
	this_ip = ifconfig.split()[1]
	netmask = ifconfig.split()[3]
	network = '.'.join(this_ip.split('.')[0:3] + ['0-255'])
	hosts = subprocess.getoutput(f'nmap -n -sn {network} -oG - | awk' + ' "/Up$/{print $2}"').split()
	for index,item in enumerate(hosts):
		if item == 'Host:':
			ip_list.append(hosts[index + 1])
	ip_list.remove(this_ip)
	print(ip_list)

def main():
	find_hosts()
	exit(0)

if __name__ == '__main__':
	main()
