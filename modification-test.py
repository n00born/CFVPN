__author__ = 'nicklewi'

import string
import socket
from numbers import Number
import random
import re
import textwrap

print("================================================================================")
print(
    textwrap.fill("Thank you for using ZPN. This interface will take you through the process of setting an IPSEC VPN connection from this server to your remote peer.",80))
print("================================================================================")







#Function to open a file(filename), search it for text(searchtext), and replace each found text with (replacetext)
def findandreplace(filename, replacement, template):

    #Open file, split into a list
    file = open(filename, "r+")

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

encryption_algorithm = "aes128"
hash_algorithm = "sha1"
dh_group = "2"
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


findandreplace("./Modified/bgpd.txt", {"<LOCAL ASN>":local_asn, "<LOCAL PUBLIC IP>":local_public_ip, "<LOCAL TUNNEL IP>":local_tunnel_ip, "<LOCAL SUB>":local_sub, "<REMOTE TUNNEL IP>":remote_tunnel_ip.split("/", 1)[0], "<REMOTE ASN>":peers_asn}, bgpdtemplate)

"""
findandreplace("./Modified/bgpd.txt", "<LOCAL TUNNEL IP>", local_tunnel_ip)
findandreplace("./Modified/bgpd.txt", "<REMOTE TUNNEL IP>", remote_tunnel_ip)
findandreplace("./Modified/bgpd.txt", "<REMOTE ASN>", peers_asn)
findandreplace("./Modified/bgpd.txt", "<LOCAL SUB>", local_sub)
"""

print("\n")
summary()