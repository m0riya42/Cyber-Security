# ARP Spoofing Detection
## Ways to Recognize ARP spoofing 

### Options which can lead to ARP SPOOFING.
* Duplicated address in the ARP table.
* To many ARP REPLAYs in small amount of time.
* More than 3 packets of the same IP address in 10 seconds.
* Duplicated Packet- the same IP address with diffrent MAC address.
* Check if the MAC address is belong to the IP address. (using get_mac_address function) 

in Order to Detect an Attack, the code is checking how many options from above is happenning.

### Conclusions
<b>less than 2 options: </B> probably there is no Attack.
<b>between 2 and 3 options: </B> the computer may be at risk.
<b>between 4 and 5 options: </B> you are under attack.

in order to protect the computer, we set the ARP table with static address using the command:
os.system("arp -s " + attacked_ip_addres+" " + real_mac_address)




