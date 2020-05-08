# modules in standard library
import socket
import sys
import json

# external modules
from subdomain import sublist3r
from service import service
from ssh_brute import ssh_login_brute

#Color
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


domain = 'beltelecom.by'


def print_json(json_list):
    print(f"{G}\nResult:")
    print(json.dumps(json_list, indent=4, sort_keys=True))
    print(W)

def write_final():
    write_dict = {ip:{"domain":domain_name_list.get(ip), "service":service_list.get(ip)} for ip in set(domain_name_list)}
    for ip in set(service_list):
        write_dict[ip]['service'][22] = {'username': ssh_login.get(ip)}
    with open('intelligence.txt', 'w') as file:
        json.dump(write_dict, file, indent=4, sort_keys=True)


domain_name_list = sublist3r.interactive(domain, '')
print_json(domain_name_list)

service_list = service.scan_service(set(domain_name_list))
print_json(service_list)

ssh_login = ssh_login_brute.ssh_login_hack([key for key,value in service_list.items() if 22 in value])
print_json(ssh_login)

write_final()

