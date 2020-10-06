# trunker
Python3 - Create virtual sub-interface (VLAN) on debian linux (primarily Kali 2020)
		- determine if the appropriate kernel modules are loaded, if not it will recommend the appropriate command
		- can add interfaces manually (-a) or through a file (-f FILE)
		- interfaces will persist through a reboot
		- remove all virtual sub-interfaces (-r)
		- logs all commands/actions to trunker.log in default location, if default location is not found the user can provide a new location
			- searches file system for trunker.log and provides file paths to each
	- TODO
		- develop listner function to capture PCAP, identify VLAN tags, and create interfaces
