import subprocess, time


while True:
	subprocess.call('wget 192.168.171.1')
	time.sleep(60)