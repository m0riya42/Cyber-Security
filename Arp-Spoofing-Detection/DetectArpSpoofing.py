

from scapy.all import *
from getmac import get_mac_address
from scapy.layers.l2 import ARP, Ether
import os
from collections import Counter
import easygui
import subprocess


def print_message(message):
    #subprocess.run(["/usr/bin/notify-send", "--icon=error", message])
    easygui.msgbox(message, title="Warning")


a = []
b = []
c = []
d = []
count = 0
attacker_ip = ""
real_mac = ""
flag = False


os.system("arp -a> f1")
with open("f1", "r") as f:
    for line in f:
        a.append(line.split()[1][1:-1])
        b.append(line.split()[3])

if len(set(b)) != len(b):
    count += 1
    print("test_1: ")
    print(set(b))
    print(b)

pkt_sniff = sniff(filter="arp", timeout=10)
for pkt in pkt_sniff:
    if pkt[ARP].op == 2: # and pkt[Ether].dst == get_mac_address():
        c.append(pkt[ARP].psrc)
        d.append(pkt[Ether].src)
if len(pkt_sniff) * 0.7 <= len(c):
    count += 1
    print("test_2: ")
    print(list(zip(c,d)))

if len(c) !=0:
    if Counter(c).most_common(1)[0][1] > 3:
        attacker_ip = Counter(c).most_common(1)[0][0]
        count += 1
        print("test_3 ")

if len(set(zip(c, d))) != len(dict(set(zip(c, d)))):
    count += 1
    print("test_4: ")
    print(set(zip(c,d)))
    print(dict(set(zip(c,d))))
    real_mac = get_mac_address(ip=attacker_ip)
    print("test_4_1: "+attacker_ip + " : " + real_mac)

for add in zip(a, b):  # check this special
    if get_mac_address(ip=add[0]) != add[1]:
        if add[1]!="<incomplete>":
            attacker_ip = add[0]
            real_mac = get_mac_address(ip=add[0])
            print("test_5: "+attacker_ip + " : " + real_mac+ ", not-real: "+add[1])
            flag = True

if flag:
    count += 1

print(count)
if count < 2:
    print_message("Don't worry everything is ok")

elif count == 2 or count == 3:
    print_message("Your computer may be at risk")

else:
    print_message("Beware! You are under attack")
    os.system("arp -s " + attacker_ip + " " + real_mac)
    print_message("The threat has been eliminated, You are safe now")


# os.system("arp -s " + attacker_ip + " " + real_mac)