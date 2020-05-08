# modules in standard library
import sys
import json

# external modules
from service import masscan
from tqdm import tqdm


#Color
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


def banner():
    print("""%s
    ╔═══╗╔═══╗╔═══╗╔╗──╔╗╔══╗╔═══╗╔═══╗
    ║╔═╗║║╔══╝║╔═╗║║╚╗╔╝║╚╣─╝║╔═╗║║╔══╝
    ║╚══╗║╚══╗║╚═╝║╚╗║║╔╝─║║─║║─╚╝║╚══╗
    ╚══╗║║╔══╝║╔╗╔╝─║╚╝║──║║─║║─╔╗║╔══╝
    ║╚═╝║║╚══╗║║║╚╗─╚╗╔╝─╔╣─╗║╚═╝║║╚══╗
    ╚═══╝╚═══╝╚╝╚═╝──╚╝──╚══╝╚═══╝╚═══╝
    """ % W)

def scan_service(ips):
    banner()
    print(f"[-] Enumerating service now{W}")
    result_scan_list = {}
    unreachable_network = 0
    for ip in tqdm(ips):
        try:
            scan = masscan.PortScanner().scan(ip, ports='7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9443,9999-10000,10443,32768,49152-49157', arguments='--max-rate 1000')
            result_scan_list[ip] = list(set(scan['scan'][str(ip)]['tcp']))
        except Exception:
            unreachable_network+=1
    if unreachable_network: print(f"{Y}[!] {unreachable_network} / {len(ips)} network is unreachable{W}")
    unreachable_network = 0
    r_dict = {key:{port:"" for port in value} for key,value in result_scan_list.items()}
    return r_dict
