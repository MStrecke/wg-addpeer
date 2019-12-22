#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Generate a new config for a WireGuard peer
# store it in its subdirectory
# add it to server config
# display new config as QR code

import subprocess
import argparse
import re
import sys
import os

# filenames used for client peer
PEER_PRIVATE_KEY_FILENAME = "private.key"
PEER_PUBLIC_KEY_FILENAME = "public.key"
PEER_PRESHARED_KEY_FILENAME = "psk.key"
PEER_CONFIG_FILENAME = "config.txt"

def analyse_server_config(filename, endpoint=None):
    """ scan config file

    :param filename: filename of config file
    :type filename: str
    :param endpoint: public IP of server (if set on the command line)
    :type endpoint: str, defaults to None
    :return: IP address of interface, next available IP address in subnet
    :rtype: two strings
    """
    # only IPV4 addresses with or without /32 suffix
    SINGLE_IP_COMP = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)(?:/32)?(?:\s|,|$)")

    public_ip = None
    listen_port = "51820"
    interface_addr = None
    interface_private_key = None
    peer_addr = []

    # parse server configuration

    current_section = None
    with open(filename, "r", encoding="utf8") as fin:
        while True:
            inl = fin.readline()
            if inl == '':
                break
            inl = inl.rstrip()
            if inl == "":
                continue

            # special case for `# public_ip`
            if inl.lower().startswith('# public_ip'):
                inl = inl[1:].strip()

            # skip comments
            if inl.startswith('#'):
                continue

            if inl[0] == "[" and inl[-1] == "]":
                # get section header
                current_section = inl[1:-1]
            else:
                # get key/value pair
                p = inl.find("=")
                if p == -1:
                    print("Error: Incorrect key/value format:", inl)
                    sys.exit(1)

                key = inl[:p].strip().lower()
                value = inl[p+1:].strip()

                if current_section == "Interface":
                    if key == "address":
                        ma = SINGLE_IP_COMP.search(value)
                        if ma is not None:
                            interface_addr = [ int(x) for x in ma.groups() ]
                    if key == "listenport":
                        listen_port = value
                    if key == "privatekey":
                        interface_private_key = value.encode("utf8")
                    if key == "public_ip":
                        public_ip = value

                # Look for other peers' 32 bit addresses
                elif current_section == "Peer":
                    if key == "allowedips":
                        for ma in SINGLE_IP_COMP.findall(value):
                            peer_addr.append([int(x) for x in ma])

    if interface_addr is None:
        print("Error: No address found in section [Interface]")
        sys.exit(2)

    if interface_private_key is None:
        print("Error: No private key found in section [Interface]")
        sys.exit(3)

    # if subnet (/24) matches, look for largest number
    next_addr = interface_addr.copy()
    if peer_addr != []:
        # find max
        for ele in peer_addr:
            if ele[0:2] == next_addr[0:2]:
                if ele[3] > next_addr[3]:
                    next_addr[3] = ele[3]

    # add 1, check for max. value
    next_addr[3] += 1
    if next_addr[3] > 255:
        print("Error: next available address would be > 255")
        sys.exit(4)

    # use endpoint from command line if provided
    # otherwise use public_ip from config file
    endpoint_n = endpoint
    if endpoint_n is None:
        endpoint_n = public_ip

    if endpoint_n is not None:
        endpoint_n = endpoint_n + ':' + listen_port

    return \
        "%d.%d.%d.%d" % (interface_addr[0], interface_addr[1], interface_addr[2], interface_addr[3]), \
        "%d.%d.%d.%d" % (next_addr[0], next_addr[1], next_addr[2], next_addr[3]), \
        endpoint_n, \
        interface_private_key


parser = argparse.ArgumentParser(description='create peer keys and configuration')
parser.add_argument('config', help='name of server configuration file')
parser.add_argument('device', help='name of new device')
parser.add_argument('--noqr', action='store_true', help='don\'t show peer config as QR code')
parser.add_argument('--public_ip', help='public IP of server')
parser.add_argument('--keep_alive', type=int, default=25,
        help='number of seconds for peer\'s keepalive packets (in secs, 0=off)')
parser.add_argument('--dns', type=str, help='DNS setting in [Interface] section')
parser.add_argument('--route_all', action='store_true', help="route all traffic through the tunnel")


args = parser.parse_args()

server_config_filename = args.config
name_of_peer = args.device

if os.path.exists(name_of_peer):
    print("Error: folder %s already exists" % name_of_peer)
    sys.exit(5)

server_internal_ip, client_next_ip, server_endpoint, server_private_key = analyse_server_config(server_config_filename, endpoint=args.public_ip)

if server_endpoint is None:
    print("Error: Endpoint for server could not be determined")
    sys.exit(6)

# get server's public key
server_public_key = subprocess.check_output(
    ["wg", "pubkey"], input=server_private_key)

# get keys for new peer
peer_private_key = subprocess.check_output(["wg", "genkey"])
peer_public_key = subprocess.check_output(["wg", "pubkey"], input=peer_private_key)
preshared_key = subprocess.check_output(["wg", "genkey"])

# create folder for these keys and config
os.umask(0o77)
os.makedirs(name_of_peer)

# Write keys to disk
open(os.path.join(name_of_peer, PEER_PRIVATE_KEY_FILENAME), "wb").write(peer_private_key)
open(os.path.join(name_of_peer, PEER_PUBLIC_KEY_FILENAME), "wb").write(peer_public_key)
open(os.path.join(name_of_peer, PEER_PRESHARED_KEY_FILENAME), "wb").write(preshared_key)

# create peer config

peer_config_txt = """[Interface]
Address = {client_address}/32
PrivateKey = {client_private_key}
""".format(
    client_address=client_next_ip,
    client_private_key=peer_private_key.decode("utf8").rstrip(),
)

if args.dns is not None:
    peer_config_txt += """DNS = %s
""" % (args.dns)

if args.route_all:
    allowed_ips = "0.0.0.0/0"
else:
    allowed_ips = "%s/32" % server_internal_ip

peer_config_txt += """
[Peer]
PublicKey = {server_public_key}
PresharedKey = {preshared_key}
AllowedIPs = {allowed_ips}
Endpoint = {server_endpoint}
""".format(
    server_public_key = server_public_key.decode("utf8").rstrip(),
    preshared_key = preshared_key.decode("utf8").rstrip(),
    allowed_ips = allowed_ips,
    server_endpoint = server_endpoint
)

if args.keep_alive != 0:
    peer_config_txt += """PersistentKeepalive = %s
""" % (args.keep_alive,)

open(os.path.join(name_of_peer, PEER_CONFIG_FILENAME), "w").write(peer_config_txt)

# append peer to "server" config
with open(server_config_filename, "a") as fout:
    fout.write("""
# %s
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
""" % ( name_of_peer,
        peer_public_key.decode("utf8").rstrip(),
        preshared_key.decode("utf8").rstrip(),
        client_next_ip
))

# show peer config as QR code
if not args.noqr:
    qrcode = subprocess.check_output(["qrencode", "-t", "utf8"], input=peer_config_txt.encode("utf8"))
    print(qrcode.decode("utf8"))
