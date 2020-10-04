import netifaces
from scapy.all import srp, Ether, ARP


def get_network_info():
    device = netifaces.gateways()['default'][netifaces.AF_INET][1]
    gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    mac = netifaces.ifaddresses(device)[netifaces.AF_LINK][0]['addr']
    ip = netifaces.ifaddresses(device)[netifaces.AF_INET][0]['addr']
    mask = netifaces.ifaddresses(device)[netifaces.AF_INET][0]['netmask']
    msg = "Device: {}, Gateway: {}, IP: {}, MASK: {}, MAC: {}.".format(device, gateway, ip, mask, mac)
    print(msg)
    return str(gateway), str(mask)


def get_netmask_len(mask):
    result = ""
    for num in mask.split('.'):
        temp = str(bin(int(num)))[2:]
        result = result + temp
    netmask_len = len("".join(str(result).split('0')[0:1]))
    return netmask_len


def send_arp_request(lan):
    ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(pdst=lan), timeout=2)
    for snd, rcv in ans:
        cur_mac = rcv.sprintf("%Ether.src%")
        cur_ip = rcv.sprintf("%ARP.psrc%")
        print(cur_mac + ' - ' + cur_ip)


if __name__ == '__main__':
    ip, mask = get_network_info()
    send_arp_request(str(ip) + '/' + str(get_netmask_len(mask)))
