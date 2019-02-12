import subprocess, time

def main():
	while True:
		subprocess.call('wget 192.168.171.1')
		time.sleep(60)

if __name__ == '__main__':
	main()