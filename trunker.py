#!/usr/bin/python3

import argparse
import subprocess
import logging
import sys
from IPy import IP


class Trunker:
    def __init__(self, vdevices, interface):
        # class vairables
        self.vdevices = int(vdevices)
        self.interface = interface
        self.log_path = "root/site-data/logs/"
        self.if_path = "/etc/network/interfaces"
        self.if_path_orig = self.if_path + ".orig"
        self.border = "*" * 50

        # Run 'updatedb'
        subprocess.run(['updatedb'], capture_output=True, check=True, text=True)

        # Run lsmod, capture output, grep for '8021q'
        lsmod = subprocess.run(['lsmod'], capture_output=True, check=True, text=True)
        
        try:
            subprocess.run(['grep', '8021q'], input=lsmod.stdout, capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError:
            print(f"It appears 8021q module is not loaded \n Run: 'modprobe 8021q'")
            sys.exit()



    def log_creation(self):
        #  locate trunker.log
        locate = subprocess.run(['locate', 'trunker.log'], capture_output=True, check=True, text=True)
        
        if len(subprocess.Popen(["ls", self.log_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[1]) > 0:
            while True:
                try:
                    print(f"{self.border}\n{self.log_path} does not exist.\nI found the following path(s) for trunker.log:")
                    # Print trunker.log locations
                    for i in locate.stdout.split('\n'):
                        print(f"{i}")
                    print(f"{self.border}\n")
                    log_file = input("Please enter a filepath for trunker.log: ")
                    if len(log_file) <= 0:
                        raise ValueError
                    logging.basicConfig(filename=log_file + "trunker.log", format="%(asctime)s %(message)s", level=logging.DEBUG, datefmt="%m/%d/%Y %H:%M:%S")
                    return print(f"{log_file}trunker.log created. Logging started")
                except FileNotFoundError:
                    print(f"{log_file} does not exist. Enter another")
                    continue
                except ValueError:
                    print(f"Filepath must not be blank!\n\n")
                    continue
        else:
            logging.basicConfig(filename=self.log_path + "trunker.log", format="%(asctime)s %(message)s", level=logging.DEBUG, datefmt="%m/%d/%Y %H:%M:%S")


    def interfaces_check(self):
        try:
            if len(subprocess.Popen(["ls", "-a", self.if_path_orig], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]) > 0:
                logging.info(f"{self.if_path_orig} already exists")
                logging.info(f"Appending devices to {self.if_path}")
                raise ValueError
            else:
                subprocess.Popen(["cp", "-p", self.if_path, self.if_path_orig]).communicate()
                logging.info(f"{self.if_path_orig} does not exist")
                logging.info(f"Copied {self.if_path} -> {self.if_path_orig}")
                print(f"{self.if_path} found.  Creating backup at {self.if_path_orig}")
        except ValueError:
            print(f"{self.if_path_orig} already exists")
            print(f"Appending devices to {self.if_path}")


    def vlan_search(self):
        logging.info(f"Beginning Search For VLAN tags on: {self.interface}")
        print(f"Beginning search for VLAN tags on: {self.interface}")
        tshark = subprocess.run(['tshark', '-O STP', '-a', 'duration:5', '-F k12text', '>', 'tsharkDump.txt'],
                                 capture_output=True, check=True, text=True)


    def add(self):
        self.log_creation()
        self.interfaces_check()
        self.vlan_search()
        for vlans in range(self.vdevices):
            vlan_num = vlans + 1

            while True:
                try:
                    vlan_device_id = int(input(f"Enter VLAN ID {vlan_num}: "))
                    if len(self.get_vlan_names()) > 0:
                        if "eth0." + str(vlan_device_id) in self.get_vlan_names():
                            raise NameError
                except ValueError:
                    print("Invalid input.  Must be an integer")
                    continue
                except NameError:
                    print(f"VLAN ID {vlan_device_id} Already Exist. Enter another")
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

            if not vlan_device_name:
                return print("Virtual Device already exists. Try running ./trunker.py -r")
            else:
                print(f"VLAN {vlan_device_name} created\nIP Address: {device_ip}/{device_cidr}")
                logging.info(f"Virtual Device {vlan_device_name} created.  Assigned IP Address {device_ip}/{device_cidr}")


    def get_vlan_names(self):
        get_vlan_names = subprocess.Popen(["ls", "-a", "/proc/net/vlan"], stdout=subprocess.PIPE).communicate()[0]
        match_names = [s for s in get_vlan_names.decode("utf-8").split("\n") if "eth0." in s]
        return match_names

    def delete(self):
        self.log_creation()
        match_names = self.get_vlan_names()
        for device in match_names:
            delete_vlan = subprocess.Popen(["ip", "link", "delete", device])
            print(f"Deleted: {device}")
            logging.info(f"Deleted: {device}")

        err = subprocess.Popen(["mv", self.if_path_orig, self.if_path], stderr=subprocess.PIPE).communicate()[1]
        logging.info(f"Moved {self.if_path_orig} -> {self.if_path}")

    def from_file(self, input_file):
        self.log_creation()
        self.interfaces_check()
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
            if not vlan_device_name:
                return print("Virtual Device already exists. Try running ./trunker.py -r")
            else:
                print(f"VLAN {vlan_device_name} created\nIP Address: {device_ip}/{device_cidr}")
                logging.info(f"Virtual Device {vlan_device_name} created from file: '{input_file.name}'")
                logging.info(f"Assigned IP Address {device_ip}/{device_cidr}")

    def make_persist(self, vlan_device_name, device_ip, device_nm):
        logging.info(f"Adding VLAN device {vlan_device_name} to {self.if_path}")
        with open(self.if_path, "a+") as interfaces:
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
                                               "type", "vlan", "id", str(vlan_device_id)], stderr=subprocess.PIPE)

        err = create_vlan_device.communicate()
        if len(err[1]) > 0:
            return False

        subprocess.Popen(["ip", "addr", "add", prefix_ip, "brd", str(device_nm),
                          "dev", vlan_device_name])
        subprocess.Popen(["ip", "link", "set", vlan_device_name, "up"])

        self.make_persist(vlan_device_name, device_ip, device_nm)

        return vlan_device_name


def main():
    print('BETA -- TESTING AUTOMATED VLANS')
    parser = argparse.ArgumentParser(description="Use to add/remove VLAN ID to default 'eth0' interface", formatter_class=argparse.RawDescriptionHelpFormatter)
    manual_group = parser.add_mutually_exclusive_group()
    manual_group.add_argument("-a", "--add", action="store_true", help="Add a single VLAN device. Combine with -n to create multiple")
    manual_group.add_argument("-r", "--rem", action="store_true", help="Remove all VLAN devices from /proc/net/vlan and /etc/network/interfaces")
    file_group = parser.add_mutually_exclusive_group()
    file_group.add_argument("-n", "--num", type=int, default=1, help="Number of VLAN devices needed (default: 1)")
    file_group.add_argument("-f", "--file", help="""Adds VLAN id's from a comma delimitted, multilined file.\nExample:\n1,192.168.1.1,24\n2,192.168.2.1,8""", type=argparse.FileType('r'))
    parser.add_argument("-i", "--inter", default="eth0", help="Specify which interface to add VLAN to")
    args = parser.parse_args()

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
