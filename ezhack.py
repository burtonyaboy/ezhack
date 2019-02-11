import ezhack

import subprocess

host_folder = '../hosts/'

class Host:
    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.hostname = hostname
        self.scanxml = host_folder + hostname + '.xml'
        self.exploits_file = host_folder + hostname + '.json'
        self.exploits = []
        self.host.session = None
        self.backdoor_port = -1

def scan_for_hosts(interface='eth0'):
	ip_list = []
	# Check the current network configuration
	ifconfig = subprocess.getoutput(f'ifconfig {interface} | grep  " inet "')
	this_ip = ifconfig.split()[1]
	netmask = ifconfig.split()[3]
	network = '.'.join(this_ip.split('.')[0:3] + ['0-255'])
	# Scan the network for live hosts
	hosts = subprocess.getoutput(f'nmap -n -sn {network} -oG - | awk' + ' "/Up$/{print $2}"').split()
	for index,item in enumerate(hosts):
		if item == 'Host:':
			ip_list.append(hosts[index + 1])
	ip_list.remove(this_ip)
	return ip_list

def scan_target(host):
	# More flexibility can be added later, this is fine for now
	subprocess.call(f'nmap -A -T5 --script=banner {host.ip_addr} -oX {host.scanxml} -e eth0')

def lookup_exploit(host):
	
	# Use searchpsloit to query for exploits
	ssploit_cmd = 'searchsploit --nmap ' + str(host.scanxml) + ' --json'
	print('[*]' + ssploit_cmd)
	if(not search_debug):
		host.exploits = subprocess.check_output(ssploit_cmd.split()).decode('utf-8')
		sys.stdout.flush()
		with open(host.exploits_file, 'w') as fi:
			fi.write(str(host.exploits))

	# Convert output to JSON
	data_json = []
	#open the raw output file
	with open(host.exploits_file, 'r') as fi:
		#read the file minus the first two lines (they are garbage)
		data = '\n'.join(fi.read().splitlines()[2:])
		#each exploit is separated by 3 newline chars
		for exp in data.split('\n\n\n'):
			data_json.append(json.loads(exp))
	#now that we have a json object, loop through and add them
	#to exploits usable on the host
	for i in data_json: 
		if len(i['RESULTS_EXPLOIT']):
			for exp in i['RESULTS_EXPLOIT']:
				if 'Metasploit' in exp['Title']: 
					print('\n[*]EXPLOIT FOUND: ' + str(exp))
					host.exploits.append(exp)
	
	# Pick an exploit to use
	#for now this will be hard-coded to use one exploit
	exploits = []
	exp_num = '16922'
	#make the directory if it doesn't exist
	if not (os.path.exists(msf_exploit_dir)):
		print('path not here!')
		os.makedirs(msf_exploit_dir)
	#mirror the exploit being used
	for exploit in host.exploits:
		if exploit['EDB-ID'] == exp_num:
			ssquery = "searchsploit -m " + exploit['EDB-ID']
			ssproc = subprocess.Popen(
				ssquery.split(),
				stdout = subprocess.PIPE)
			sys.stdout.flush()
			ssproc.communicate()
			#grab the ID of the exploit
			#msf updated so now most of these don't work
			#the ID can be used to find an equivalent exploit 
			with open(exp_num + '.rb', 'r') as file:
				exploit = file.readlines()
			exploits.append(exploit[1].split()[2].split('.')[0])
			subprocess.call(['rm', exp_num + '.rb'])
	#override the old exploit data 
	host.exploits = exploits
	return 0


def main():
	pass

if __name__ == "__main__":
	main()