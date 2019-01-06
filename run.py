#/usr/bin/python3


import exploit, post_exploit, scan_target, lookup_exploit


# GLOBALS TO BE REPLACED BY COMMAND LINE ARGUMENTS
HOSTS = ['192.168.171.128']

class Host:

    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.hostname = hostname
        self.scanxml = hostname + '.xml'
        self.exploits_file = hostname + '.json'
        self.exploits = []
        self.host.session = None
        self.backdoor_port = -1


def main():
	exploit.exploit()

if __name__ == "__main__":
	main()