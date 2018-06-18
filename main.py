#!/usr/bin/python
# -*- coding: utf-8 -*- 
import subprocess
import xmltodict
import os
import sys

#global variables to be later changed to user input
hosts = ['127.0.0.1']
intensity = 'Loud'

#host object holds information about a target
class Host:

    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.open_ports = {}
        self.os_info = {}

#has a flexible network scanner and parses data
#to format which is useful for metasploit
class NetworkScanner:

    def __init__(self):
        self.nmap_command = ""
        self.nmap_process = None
        self.target_info = ""
        self.output_type = "-oX" #outputs xml file
        self.output_file = "scan.xml"
        self.options_list = {
            None: '-F',
            'Quiet' : '-sS -T3 -f',
            'Normal' : '-sV -T4 --script=banner',
            'Loud' : '-A -T5 --script=banner'
        }
        print("[+]Scanner initialized.")

    #perform scan with nmap
    def nmap_scan(self, host_ip, options):
        #create command for nmap to execute
        self.nmap_command = "nmap " + \
            self.options_list[options] + " " + \
            str(host_ip) + " " + \
            self.output_type + " " + \
            self.output_file
        print("[*]" + self.nmap_command)
        #execute command and wait for it to finish
        self.nmap_process = subprocess.Popen(
            self.nmap_command,
            shell=True,
            stdout=subprocess.PIPE)
        sys.stdout.flush()
        self.nmap_process.communicate()

    #main controller of the scanner
    def scan_network(self, host, options):
        self.nmap_scan(host.ip_addr, options)
        host.open_ports = self.parse_target_data()
        return 0

    #make the scanned data easier to use
    def parse_target_data(self):
        #convert xml data to a dictionary object
        open_ports = {}
        with open(self.output_file) as f: 
            target = xmltodict.parse(f.read())
        #for each port grab the cpe and each of its components
        #then add this to the open_ports dictionary for the host
        try:
            for port in target['nmaprun']['host']['ports']['port']:
                open_ports.update({port['@portid'] : {
                    'protocol' : port['@protocol'],
                    'cpe': port['service']['cpe'],
                    'vendor' : port['service']['cpe'].split(':')[2],
                    'product' : port['service']['@product'],
                    'version' : port['service']['@version']
                }})
        #Parsing above doesn't work if there is only one port open
        except TypeError as e:
            try:
                port = target['nmaprun']['host']['ports']['port']
                open_ports.update({port['@portid'] : {
                    'protocol' : port['@protocol'],
                    'cpe': port['service']['cpe'],
                    'vendor' : port['service']['cpe'].split(':')[2],
                    'product' : port['service']['@product'],
                    'version' : port['service']['@version']
                }})
            except IndexError as e:
                pass
        except Exception as e:
            print("Unkown error, exiting.\n" + str(e))
            quit(-1)
        return open_ports

#use data to find a useful exploit
class DatabaseFind:

    def __init__(self):
        #set up class variables
        pass

    def search_database(self, target_info, attack_type):
        #use information gained from scanning to find an
        #appropriate vulnerability
        exploit_data = "Use exploits/windows/smb/net_api"
        return exploit_data

#actually run the exploit against the target
class Exploit:

    def __init__(self):
        #set up local variables
        pass

    def exploit(self, exploit_data, target_url):
        #execute exploit
        pass

#if necessary, first gain root
#cover tracks
#install files and programs necessary to add host to our network
class PostExploitation:

    def __init__(self):
        print("[+]Created ")

    def load_files(self):
        print("[+]Downloading and executing files.")
        print("[+]Host added to network.")

class BotController:

    def __init__(self, scanner, finder, exp, post_exp):
        self.scanner = scanner
        self.finder = finder
        self.exp = exp
        self.post_exp = post_exp
        print("[+]Controller created.")

    def exploit_target(self, host, attack_type):
        vulnerability_data = ""
        self.scanner.scan_network(host, attack_type)
        print('[+]The following services were found:')
        for port in host.open_ports:
            print("[*]Port {} is running {} {} version {}".format(
                port, 
                host.open_ports[port]['vendor'], 
                host.open_ports[port]['product'], 
                host.open_ports[port]['version']))
        exploit_data = self.finder.search_database(vulnerability_data, attack_type)
        self.exp.exploit(exploit_data, host.ip_addr)
        self.post_exp.load_files()

def console():
    #make sure user is root
    uid = os.getuid()
    print("[+]CONSOLE STARTED")
    if uid is not 0:
        print("[-]THIS PROGRAM REQUIRES ROOT PRIVILEGE")
        print("[-]YOUR UID IS: " + str(uid))
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
        host = Host(ip)
        controller.exploit_target(host, intensity)


