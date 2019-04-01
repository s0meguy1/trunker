#!/usr/bin/python3

# Need to figure out how to check vlan_device_id against create vlan devices.  Other wise the user won't get 
# alerted that the device is in use until after they've submitted IP and CIDR.

import argparse
import subprocess
import logging
from IPy import IP

class Trunker:
    def __init__(self, vdevices, interface, persistance = False):
        # class vairables
        self.vdevices = int(vdevices)
        self.interface = interface
        self.persistance = persistance

        logging.basicConfig(filename = "/root/site-data/logs/trunker.log", format="%(asctime)s %(message)s", level = logging.DEBUG, datefmt="%m/%d/%Y %H:%M:%S")

        if self.persistance:
            logging.info("Persistance flag set")
            if len(subprocess.Popen(["ls", "-a", "/etc/network/interfaces.orig"], stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()[0]) > 0:
                logging.info("/etc/network/interfaces.orig already exists.")
                pass
            else:
                subprocess.Popen(["cp", "-p", "/etc/network/interfaces", "/etc/network/interfaces.orig"]).communicate()
                logging.info("Copied /etc/network/interfaces -> /etc/network/interfaces.orig")

    def add(self):
        for vlans in range(self.vdevices):
            vlan_num = vlans + 1

            while True:
                try:
                    vlan_device_id = int(input(f"Enter VLAN ID {vlan_num}: "))
                except ValueError:
                    print("Invalid input.  Must be an integer")
                    continue
                else:
                    break

            while True:
                try:
                    device_ip = IP(input(f"Enter IPv4 address for VLAN device {vlan_device_id}: "))
                except ValueError:
                    print("Invalid input. Must be a valid IPv4 Address")
                    continue
                else:
                    break

            while True:
                try:
                    device_cidr = int(input(f"Enter CIDR notation for {device_ip}: "))
                    if device_cidr < 0 or device_cidr > 31:
                        raise ValueError
                except ValueError:
                    print("Invalid input. Must be valid CIDR notation")
                    continue
                else:
                    break

            device_nm = self.cidr_to_netmask(device_cidr)
            vlan_device_name = self.vconfig(vlan_device_id,
                                            device_ip,
                                            device_nm)

            if vlan_device_name == False:
                return print("Virtual Device already exists. Try running ./trunker.py -r")
            else:
                print(f"VLAN {vlan_device_name} created\nIP Address: {device_ip}/{device_cidr}")
                logging.info(f"Virtual Device {vlan_device_name} created.  Assigned IP Address {device_ip}/{device_cidr}")

            if self.persistance:
                self.make_persist(vlan_device_name, device_ip, device_nm.netmask())

    def delete(self):
        get_vlan_names = subprocess.Popen(["ls", "-a", "/proc/net/vlan"], stdout = subprocess.PIPE).communicate()[0]
        match_names = [s for s in get_vlan_names.decode("utf-8").split("\n") if "eth0." in s]
        for device in match_names:
            delete_vlan = subprocess.Popen(["ip", "link", "delete", device])
            print(f"Deleted: {device}")
            logging.info(f"Deleted: {device}")

        err = subprocess.Popen(["mv", "/etc/network/interfaces.orig", "/etc/network/interfaces"], stderr = subprocess.PIPE).communicate()[1]
        logging.info("Moved /etc/network/interfaces.orig -> /etc/network/interfaces")

    def from_file(self, input_file):
        for line in input_file:
            vlan_device_id, device_ip, device_cidr = line.split(",")[0:3] 
            device_cidr = device_cidr.strip()

            try:
                int(vlan_device_id)
            except ValueError:
                print(f"File contains invalid VLAN Device ID ({vlan_device_id}). Must be a valid integer.")
                print("Run 'trunker -r' before trying again")
                break

            try:
                IP(device_ip)
            except ValueError:
                print(f"File contains invalid IPv4 Address ({device_ip})")
                print("Run 'trunker -r' before trying again")
                break

            try:
                int(device_cidr)
                if int(device_cidr) < 0 or int(device_cidr) > 31:
                    raise ValueError
            except ValueError:
                print(f"File contains invalid CIDR Notation ({device_cidr})")
                print("Run 'trunker -r' before trying again")
                break

            device_nm = self.cidr_to_netmask(int(device_cidr)) 
            vlan_device_name = self.vconfig(vlan_device_id,
                                                device_ip,
                                                device_nm)
            if vlan_device_name == False:
                return print("Virtual Device already exists. Try running ./trunker.py -r")
            else:
                print(f"VLAN {vlan_device_name} created\nIP Address: {device_ip}/{device_cidr}")
                logging.info(f"Virtual Device {vlan_device_name} created from file: '{input_file.name}'")
                logging.info(f"Assigned IP Address {device_ip}/{device_cidr}")

    def make_persist(self, vlan_device_name, device_ip, device_nm):
        print(f"Adding VLAN device {vlan_device_name} to /etc/network/interfaces")
        logging.info(f"Adding VLAN device {vlan_device_name} to /etc/network/interfaces")
        with open("/etc/network/interfaces", "a+") as interfaces:
            interfaces.write("\n# VLAN device {} added by trunker\nauto {}\niface {} inet static\n\taddress {}\n\tnetmask {}\n\tvlan-raw-device {}\n".format(
                        vlan_device_name,
                        vlan_device_name,
                        vlan_device_name,
                        device_ip,
                        device_nm,
                        self.interface
            ))

    def cidr_to_netmask(self, device_cidr):
        device_nm = ''
        for i in range(4):
            if device_cidr > 7:
                device_nm += "255."
            else:
                dec = 255 - (2**(8 - device_cidr) - 1)
                device_nm += str(dec) + "."
            device_cidr -= 8
            if device_cidr < 0:
                device_cidr = 0
        return device_nm[:-1]

    def vconfig(self, vlan_device_id, device_ip, device_nm):
        vlan_device_name = "%s.%s" % (self.interface, str(vlan_device_id))
        prefix_ip = "%s/%s" % (str(device_ip), str(device_nm))
        create_vlan_device = subprocess.Popen(["ip", "link", "add", "link", self.interface, "name", vlan_device_name,
                                               "type", "vlan", "id", str(vlan_device_id)], stderr = subprocess.PIPE)

        err = create_vlan_device.communicate()
        if len(err[1]) > 0:
            return False

        subprocess.Popen(["ip", "addr", "add", prefix_ip, "brd", str(device_nm),
                                                 "dev", vlan_device_name])
        subprocess.Popen(["ip", "link", "set", vlan_device_name, "up"])

        return vlan_device_name

def main():
    parser = argparse.ArgumentParser(description="Use to add/remove VLAN ID to default 'eth0' interface",formatter_class=argparse.RawDescriptionHelpFormatter)
    manual_group = parser.add_mutually_exclusive_group()
    manual_group.add_argument("-a", "--add", action="store_true", help="Add a single VLAN device. Combine with -n to create multiple")
    manual_group.add_argument("-r", "--rem", action="store_true", help="Remove all VLAN devices from /proc/net/vlan and /etc/network/interfaces")
    file_group = parser.add_mutually_exclusive_group()
    file_group.add_argument("-n", "--num", type = int, default = 1, help = "Number of VLAN devices needed (default: 1)")
    file_group.add_argument("-f", "--file", help="""Adds VLAN id's from a comma delimitted, multilined file.\nExample:\n1,192.168.1.1,24\n2,192.168.2.1,8""", type=argparse.FileType('r'))
    parser.add_argument("-i", "--inter", default = "eth0", help = "Specify which interface to add VLAN to")
    parser.add_argument("-p", "--persistance", action="store_true", help="Make VLAN devices persist through reboot")
    args = parser.parse_args()

    if args.persistance:
        vlan_trunk = Trunker(args.num, args.inter, args.persistance)
    else:
        vlan_trunk = Trunker(args.num, args.inter)

    if args.add:
        vlan_trunk.add()
    elif args.rem:
        vlan_trunk.delete()
    elif args.file:
        vlan_trunk.from_file(args.file)
    else:
        print("usage: trunker [-h] [-a ADD | -r REM | -f FILE] [-i INTER] [-n NUM]")
        print("-h, --help .... show help message:")

if __name__ == "__main__":
    main()
