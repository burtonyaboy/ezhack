#!/usr/bin/python
# -*- coding: utf-8 -*- 
import subprocess
import os
import sys
import json

#global variables to be later changed to user input
hosts = ['10.10.10.2']
intensity = 'Loud'

#global variables for debugging
#nmap doesnt need to be run every time for testing:
nmap_debug = 1
search_debug = 0

#host object holds information about a target
class Host:

    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.vulnerabilities = None
        self.hostname = hostname
        self.scanxml = hostname + '.xml'
        self.exploits_file = hostname + '.json'
        self.exploits = None
#has a flexible network scanner and parses data
#to format which is useful for metasploit
class NetworkScanner:

    def __init__(self):
        self.nmap_command = ''
        self.nmap_process = None
        self.target_info = ''
        self.output_type = '-oX' #outputs xml file
        self.options_list = {
            None: '-F',
            'Quiet' : '-sS -T3 -f',
            'Normal' : '-sV -T4 --script=banner',
            'Loud' : '-A -T5 --script=banner'
        }
        print('[+]Scanner initialized.')
    
    #main controller of the scanner
    def scan_network(self, host, options):
        #create command for nmap to execute
        self.nmap_command = 'nmap ' + \
            self.options_list[options] + ' ' + \
            str(host.ip_addr) + ' ' + \
            self.output_type + ' ' + \
            host.scanxml
        print('[*]' + self.nmap_command)
        #execute command and wait for it to finish
        if(not nmap_debug):
            self.nmap_process = subprocess.Popen(
                self.nmap_command,
                shell=True,
                stdout=subprocess.PIPE)
            sys.stdout.flush()
            print(self.nmap_process.communicate()) 
        else:
            pass
        return 0

#use data to find a useful exploit
class DatabaseFind:

    def __init__(self):
        print('[+]Finder initialized.')

    def search_database(self, host, attack_type):
        print('[+]Searching local exploit database')
        ssploit_cmd = 'searchsploit --nmap ' + str(host.scanxml) + ' --json'
        print('[+]' + ssploit_cmd)
        if(not search_debug):
            host.exploits = subprocess.check_output(ssploit_cmd.split()).decode('utf-8')
            sys.stdout.flush()
            with open(host.exploits_file, 'w') as fi:
                fi.write(str(host.exploits))
        else:
            pass
        self.output_to_json(host.exploits_file)
        return 0

    def output_to_json(self, file_name):
        #make the output into usable json
        data_json = []
        with open(file_name, 'r') as fi:
            data = '\n'.join(fi.read().splitlines()[2:])
            for exp in data.split('\n\n\n'):
                data_json.append(json.loads(exp))
        for i in data_json: 
            if len(i['RESULTS_EXPLOIT']): print(i['RESULTS_EXPLOIT'][0]['Title'])

#actually run the exploit against the target
class Exploit:

    def __init__(self):
        self.msfp = None
        print('[+]Exploit framework initialized.')

    def exploit(self, exploit_data, target_url):
        print('[+]Exploited. Creating backdoor')

#if necessary, first gain root
#cover tracks
#install files and programs necessary to add host to our network
class PostExploitation:

    def __init__(self):
        print('[+]Created ')

    def load_files(self):
        print('[+]Downloading and executing files.')
        print('[+]Host added to network.')

class BotController:

    def __init__(self, scanner, finder, exp, post_exp):
        self.scanner = scanner
        self.finder = finder
        self.exp = exp
        self.post_exp = post_exp
        print('[+]Controller created.')

    def exploit_target(self, host, attack_type):
        self.scanner.scan_network(host, attack_type)
        print('[+]The following services were found:')
        for port in host.open_ports:
            print('[*]Port {} is running {} {} version {}'.format(
                port, 
                host.open_ports[port]['vendor'], 
                host.open_ports[port]['product'], 
                host.open_ports[port]['version']))
        exploit_data = self.finder.search_database(host, attack_type)
        self.exp.exploit(exploit_data, host.ip_addr)
        self.post_exp.load_files()

def console():
    #make sure user is root
    uid = os.getuid()
    print('[+]CONSOLE STARTED')
    if uid is not 0:
        print('[-]THIS PROGRAM REQUIRES ROOT PRIVILEGE')
        print('[-]YOUR UID IS: ' + str(uid))
        exit(1)

if __name__ == '__main__':
    #set everything up
    console()
    net_scan = NetworkScanner()
    data_search = DatabaseFind()
    exp = Exploit()
    post_exploit = PostExploitation()
    controller = BotController(net_scan, data_search, exp, post_exploit)
    #loop through hosts
    for ip in hosts:
        host = Host(ip, 'vulnerable')
        controller.exploit_target(host, intensity)

