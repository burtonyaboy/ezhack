import subprocess

class NetworkScanner:

    def __init__(self):
        self.nmap_command = ""
        self.nmap_process = None
        self.options_list = {
            0: '-F',
            'Quiet': '-sS -T3 -f',
            'Normal': '-sV -T4 -O --script=banner',
            'Loud' : '-A -T5 --script=banner'
        }
        print("Scanner created.")

    def nmap_scan(self, target_url, options):
        self.nmap_command = "nmap " + str(target_url) + " " + self.options_list[options]
        self.nmap_process = subprocess.Popen(self.nmap_command, shell=True)# stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        target_info = self.nmap_process.stdout
        self.nmap_process.wait()
        return target_info

    def scan_network(self, target_url, options):
        print("Scanning network: {} with following options: {}".format(target_url, options))
        target_info = self.nmap_scan(target_url, options)
        print("Found the following from scan:\n {}".format(target_info))
        return target_info

class DatabaseFind:

    def __init__(self):
        print("Finder created.")

    def search_database(self, target_info, attack_type):
        print("Searching database for attacks of: {} with target platform: {}".format(attack_type, target_info))
        exploit_data = "Use exploits/windows/smb/net_api"
        return exploit_data

class Exploit:
    def __init__(self):
        print("Exploit framework started.")

    def exploit(self, exploit_data, target_url):
        print("Exploited. Creating backdoor")

class PostExploitation:
    def __init__(self):
        print("Created file loader.")

    def load_files(self):
        print("Downloading and executing files.")
        print("Host successfully added to botnet.")

class HostController:
    def __init__(self, scanner, finder, exp, post_exp):
        self.scanner = scanner
        self.finder = finder
        self.exp = exp
        self.post_exp = post_exp
        print("Controller created.")

    def start_exploit(self, target_url, attack_type):
        vulnerability_data = self.scanner.scan_network(target_url, attack_type)
        exploit_data = self.finder.search_database(vulnerability_data, attack_type)
        self.exp.exploit(exploit_data, target_url)
        self.post_exp.load_files()

    def ping_host(self, target_url):
        print("Pinging host")

    def test_control(self):
        print("Connected.")
        print("Executing: 'w && cname -a && netstat'")
        print("Connection closed.")

if __name__ == '__main__':
    net_scan = NetworkScanner()
    data_search = DatabaseFind()
    exp = Exploit()
    post_exploit = PostExploitation()
    controller = HostController(net_scan, data_search, exp, post_exploit)
    controller.start_exploit('127.0.0.1', 'Normal')
    controller.ping_host('127.0.0.1')
    controller.test_control()
