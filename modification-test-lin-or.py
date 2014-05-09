__author__ = 'nicklewi'

import string
import socket
from numbers import Number
import random
import re
import textwrap
import os

print("================================================================================")
print(
    textwrap.fill("Thank you for using ZPN. This interface will take you through the process of setting an IPSEC VPN connection from this server to your remote peer.",80))
print("================================================================================")







#Function to open a file(filename), search it for text(searchtext), and replace each found text with (replacetext)
def findandreplace(filename, replacement, template):

    #Open file, split into a list
    file = open(filename, "w+")
    file.truncate()
    for src, target in replacement.iteritems():
        template = template.replace(src, target)
    file.write(template)
    file.close()
    return True

def summary():
    print("Here is a summary of your configuration. This will be emailed to blah blah blah" + "\n")

    print("======================================================")
    print("                  Phase 1 Proposal                    ")
    print("======================================================" + "\n")
    print("Local public IP: ")
    print("Peer public IP: " + str(peer_public_ip))
    print("Preshared Key: " + "\"" + str(
        psk) + "\"" + "  <-- Please DO NOT include the end quotations in your preshared key" )
    print(
        "Encryption: " + str(encryption_algorithm) + ", " + str(hash_algorithm) + ", " + "dhgroup " + str(
            dh_group) + "\n")

    print("======================================================")
    print("                  Phase 2 Proposal                    ")
    print("======================================================")
    print("Remote Private LAN: " + str(remote_sub))
    print("Encryption: " + "pfs group " + str(pfs_group) + ", " + str(p2_enc_alg))
    print("SA Lifetime: " + str(p2_lifetime) + "\n")

    print("======================================================")
    print("                  BGP Configuration                   ")
    print("======================================================")
    print("Remote Tunnel IP: " + local_tunnel_ip)
    print("Local Tunnel IP: " + remote_tunnel_ip)
    print("Peers ASN: " + str(peers_asn))
    print("Local ASN: " + str(local_asn) + "\n")

bgpdtemplate = """
hostname ec2-vpn
password testPassword
enable password testPassword
!
log file /var/log/quagga/bgpd
!debug bgp events
!debug bgp zebra
debug bgp updates
!
router bgp <LOCAL ASN>
bgp router-id <LOCAL PUBLIC IP>
network <LOCAL TUNNEL IP>
network <LOCAL SUB>
!
! aws tunnel #1 neighbour
neighbor <REMOTE TUNNEL IP> remote-as <REMOTE ASN>
!

!
line vty
"""

ipsectemplate = """#!/usr/sbin/setkey -f
flush;
spdflush;

spdadd <LOCAL TUNNEL IP> <REMOTE TUNNEL IP> any -P out ipsec
   esp/tunnel/<LOCAL PRIVATE IP>-<PEER PUBLIC IP>/require;

spdadd <REMOTE TUNNEL IP> <LOCAL TUNNEL IP> any -P in ipsec
   esp/tunnel/<PEER PUBLIC IP>-<LOCAL PRIVATE IP>/require;

spdadd <LOCAL TUNNEL IP> <REMOTE SUB> any -P out ipsec
   esp/tunnel/<LOCAL PRIVATE IP>-<PEER PUBLIC IP>/require;

spdadd <REMOTE SUB> <LOCAL TUNNEL IP> any -P in ipsec
   esp/tunnel/<PEER PUBLIC IP>-<LOCAL PRIVATE IP>/require;

spdadd <LOCAL SUB> <REMOTE SUB> any -P out ipsec
   esp/tunnel/<LOCAL PRIVATE IP>-<PEER PUBLIC IP>/require;

spdadd <REMOTE SUB> <LOCAL SUB> any -P in ipsec
   esp/tunnel/<PEER PUBLIC IP>-<LOCAL PRIVATE IP>/require;
"""

psktemplate = """# IPv4/v6 addresses

<PEER PUBLIC IP>    <PSK>
"""

racoontemplate = """log notify;
path pre_shared_key "/etc/racoon/psk.txt";
path certificate "/etc/racoon/certs";

remote <PEER PUBLIC IP> {
        my_identifier address <LOCAL PUBLIC IP>;
        exchange_mode main;
        nat_traversal off;
        lifetime time 28800 seconds;
        generate_policy unique;
        proposal {
                encryption_algorithm <ENCRYPTION ALGORITHM>;
                hash_algorithm <HASH ALGORITHM>;
                authentication_method pre_shared_key;
                dh_group <DH GROUP>;
        }

}

sainfo address <LOCAL TUNNEL IP> any address <REMOTE TUNNEL IP> any {
    pfs_group <PFS GROUP>;
    lifetime time <P2 LIFETIME> seconds;
    encryption_algorithm <P2 ENC ALG>;
    authentication_algorithm hmac_sha1;
    compression_algorithm deflate;
}
"""

zebratemplate = """hostname ec2-zvpn
password testPassword
enable password testPassword
!
! list interfaces
interface eth0
interface lo
!
line vty
"""

daemonstemplate="""zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
babeld=no
"""



encryption_algorithm = "aes128"
hash_algorithm = "sha1"
dh_group = "2"
local_private_ip = "10.0.0.167"
local_public_ip = "54.186.139.150"
peer_public_ip = "54.85.25.102"
remote_tunnel_ip = "169.254.249.38/30"
local_tunnel_ip = "169.254.249.37/30"
local_sub = "10.0.0.0/24"
remote_sub = "192.168.0.0/16"
peers_asn = "65001"
local_asn = "65000"
psk = "testkey"
dh_group = "2"
pfs_group = "2"
p2_lifetime = "3600"
p2_enc_alg = "aes128"

eth0template = """# The primary network interface
auto eth0
iface eth0 inet dhcp
        post-up ip a a """ + local_tunnel_ip + " dev eth0"

#write files
findandreplace("/etc/quagga/bgpd.conf", {"<LOCAL ASN>":local_asn, "<LOCAL PUBLIC IP>":local_public_ip, "<LOCAL TUNNEL IP>":local_tunnel_ip, "<LOCAL SUB>":local_sub, "<REMOTE TUNNEL IP>":remote_tunnel_ip.split("/", 1)[0], "<REMOTE ASN>":peers_asn}, bgpdtemplate)
findandreplace("/etc/ipsec-tools.conf", {"<LOCAL TUNNEL IP>":local_tunnel_ip, "<REMOTE TUNNEL IP>":remote_tunnel_ip, "<REMOTE SUB>":remote_sub, "<LOCAL SUB>":local_sub, "<LOCAL PRIVATE IP>":local_private_ip, "<PEER PUBLIC IP>":peer_public_ip}, ipsectemplate)
findandreplace("/etc/racoon/psk.txt", {"<PEER PUBLIC IP>":peer_public_ip, "<PSK>":psk}, psktemplate)
findandreplace("/etc/racoon/racoon.conf", {"<PEER PUBLIC IP>":peer_public_ip, "<LOCAL PUBLIC IP>":local_public_ip, "<ENCRYPTION ALGORITHM>":encryption_algorithm, "<HASH ALGORITHM>":hash_algorithm, "<DH GROUP>":dh_group, "<LOCAL TUNNEL IP>":local_tunnel_ip, "<REMOTE TUNNEL IP>":remote_tunnel_ip, "<PFS GROUP>":pfs_group, "<P2 LIFETIME>":p2_lifetime, "<P2 ENC ALG>":p2_enc_alg}, racoontemplate)
findandreplace("/etc/quagga/zebra.conf", {}, zebratemplate)
findandreplace("/etc/quagga/daemons", {}, daemonstemplate)
findandreplace("/etc/network/interfaces.d/eth0.cfg", {}, eth0template)

#chmod for required files
os.system("chmod 600 /etc/racoon/psk.txt")
os.system("chmod 600 /etc/racoon/racoon.conf")

#stop/start services
os.system("service racoon stop")
os.system("service quagga restart")
os.system("service setkey restart")
os.system("service racoon start")
os.system("racoonctl vpn-connect " + peer_public_ip)

print("\n")
summary()