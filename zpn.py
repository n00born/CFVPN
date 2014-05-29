#!/usr/bin/env python

import string
import os
import sys
import random
import re
import textwrap
import stat
import time
import subprocess

#Initial arguement check
helptext = "usage: zpn.py [option] \n" \
           "-h     : Help. Shows this text.\n" \
           "-v     : Verbose. Gives verbose text on execution of the script.\n\n" \
           "If you have any questions or concerns please contact bfowler@ or nicklewi@" \
           "This is a beta script and is intended to configure an instance launched with the CloudFort Cloud Formation template in an AWS environment." \
           "This will help configure multiple linux and AWS elements to establish a VPN connection remotely.\n"
numparam = len(sys.argv)
verbose = 0

if numparam != 1:
        if numparam > 2:
                print helptext
                sys.exit()
        if sys.argv[1] == '-h':
                print helptext
                sys.exit()
        if sys.argv[1] == '-v':
                verbose = 1

#Check if sudo or not. Exits if not sudo.
if os.geteuid() != 0:
    print "--ERROR:\nPermission Denied, you must run this script as root.\n"
    sys.exit(1)

# Have user confirm SNS subscription
def subscription():
    print("\n" + textwrap.fill("Before we get started you will want to make sure that you have confirmed the SNS topic subscription sent to the email address " + os.environ['EMAIL'] + ". This is where the final VPN config will be sent to. Please hit 'ENTER' to continue after confirming subscription in your inbox.", 80))
    print("--------------------------------------------------------------------------------")
    answer = raw_input("> ")
    if answer == '':
        os.system('clear')
    else:
        print("\n"+ "Please hit enter to continue...")
        subscription()



# Use pip to install AWS unified CLI
print("Installing needed packages...")
os.system("pip install awscli")
print("\n")
os.system("wget http://s3.amazonaws.com/ec2metadata/ec2-metadata && mv ec2-metadata /usr/bin")
os.chmod('/usr/bin/ec2-metadata', stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)
os.system("clear")

#Verbose vs not
def clioutput(command):
    if verbose == 1:
        os.system(command)
    else:
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

# Validates IPs
def ipFormatChk(ip_str):
    if len(ip_str.split()) == 1:
        ipList = ip_str.split('.')
        if len(ipList) == 4:
            for i, item in enumerate(ipList):
                try:
                    ipList[i] = int(item)
                except:
                    return False
                if not isinstance(ipList[i], int):
                    return False
            if (max(ipList) < 256) & (min(ipList) > -1):
                return True
            else:
                return False
        else:
            return False
    else:
        return False

# Asks user for the VPN peer's public IP
def peers_public():
    global peer_public_ip
    print("\n" +
        textwrap.fill("Please enter the public IP of the remote peer that you want to establish an IPSEC VPN connection with (must be in format x.x.x.x):",80))
    print("--------------------------------------------------------------------------------")
    peer = raw_input("> ")
    if ipFormatChk(peer): # runs ip check before passing it into variable
        print(peer + " will be used for the peer's public IP...")
        peer_public_ip = str(peer)
        assert isinstance(peer_public_ip, object)
        return peer_public_ip
    else:
        print("\n" + "Invalid entry: Please enter the remote peer's public IP in a valid format")
        peers_public() # reruns the same function if invalid answer

# Asks user for tunnel IPs.
def peer_tunnel():
    global remote_tunnel_ip
    global local_tunnel_ip
    print(
        "\n" + textwrap.fill("Do you want Cloudfort to automatically generate the tunnel IPs for your connection (recommended), or do you want to do this manually? Please select option 1 or 2:", 80))
    print("--------------------------------------------------------------------------------")
    print("1) Let CloudFort generate tunnel IPs for this connection")
    print("2) I want to set my own tunnel IPs for both sides of the connection")
    tunnel_ip_answer = raw_input("> ")
    if tunnel_ip_answer == '2':
        def remote_ip():
            global remote_tunnel_ip
            print(
                "\n" + textwrap.fill("What tunnel IP will the REMOTE peer be using? Again, You will want to pick something in same 169.254.X.X/30 range as the LOCAL side.",80))
            print("--------------------------------------------------------------------------------")
            tunnel_ip = raw_input("> ")

            def extractIP(ipStr):
                l = re.split('(.*)\.(.*)\.(.*)\.(.*)',
                             ipStr) # function will be used to parse and check that user input is in 169.254.251.x range
                return l[1:-1]

            if ipFormatChk(tunnel_ip) and 254 >= int(extractIP(tunnel_ip)[3]) > 0 and int(
                    extractIP(tunnel_ip)[0]) == 169 and int(
                    extractIP(tunnel_ip)[1]) == 254 and 255 >= int(extractIP(tunnel_ip)[2]) > 0 and int(
                    extractIP(tunnel_ip)[3]) != int(extractIP(local_tunnel_ip)[3]):
                print(str(tunnel_ip) + " will be used for the remote tunnel IP...")
                remote_tunnel_ip = tunnel_ip

            else:
                print("\n" + textwrap.fill("Invalid entry: Please be sure the IP is valid, does not include the /30 at the end, and is not the same as the REMOTE IP", 80))
                remote_ip()

        def local_ip():
            global local_tunnel_ip
            print(
                "\n" + textwrap.fill("What tunnel IP do you want to use for the LOCAL side of this connection. (It must be 169.254.X.X/30 range. So for example you could assign the LOCAL side '169.254.251.18' and assign the REMOTE side '169.254.251.17')", 80))
            print("--------------------------------------------------------------------------------")
            tunnel_ip = raw_input("> ")

            def extractIP(ipStr):
                l = re.split('(.*)\.(.*)\.(.*)\.(.*)',
                             ipStr) # function will be used to parse and check that user input is in 169.254.x.x range
                return l[1:-1]

            if ipFormatChk(tunnel_ip) and 254 >= int(extractIP(tunnel_ip)[3]) > 0 and int(
                    extractIP(tunnel_ip)[0]) == 169 and int(extractIP(tunnel_ip)[1]) == 254 and 255 >= int(
                    extractIP(tunnel_ip)[2]) > 0:
                print(str(tunnel_ip) + " will be used for the LOCAL tunnel IP...")
                local_tunnel_ip = tunnel_ip
            else:
                print("\n" + "Invalid entry: Please be sure the IP is valid and does not include the /30 at the end")
                local_ip()

        local_ip()
        remote_ip()

    elif tunnel_ip_answer == '1' : # If user chooses '1' then a random IP is generated
        global remote_tunnel_ip
        global local_tunnel_ip
        remote_tunnel_ip = '169.254.251.1'
        print(remote_tunnel_ip + " will be used for the remote tunnel IP of this connection...")
        local_tunnel_ip = '169.254.251.2'
        print(local_tunnel_ip + " will be used for the local tunnel IP of this connection...")
    else:
        print("\n" + "Invalid entry")
        peer_tunnel()

# Asks user for peer BGP ASN
def peers_as():
    global peers_asn
    print("\n" + "Enter the BGP ASN of the REMOTE peer you are connecting to (ex.'65030'):")
    print("--------------------------------------------------------------------------------")
    peer = raw_input("> ")
    if 65536 >= int(peer) >= 0 and peer != local_asn: # Verifies that the ASN is between 0 - 65536 (valid)
        print(peer + " will be used for the REMOTE peer's ASN...")
        peers_asn = str(peer)
    else:
        print("\n" + textwrap.fill("Invalid entry: Please enter an ASN between 0-65536, and make sure it is not the same as your LOCAL ASN", 80))
        peers_as() # Reruns function if answer is invalid

# Asks user what ASN they want, and checks to make sure it is valid
def local_as():
    global local_asn
    print("\n" +
        textwrap.fill("Enter the BGP ASN of this LOCAL server.(NOTE: you must choose something between 64512 - 65536. Anything less than 64512 should be publicly registered to you):", 80))
    print("--------------------------------------------------------------------------------")
    local = raw_input("> ")
    if 64512 <= int(
            local) <= 65536: # Checking to make sure ASN selected is above 65000 (so that it is not a registered ASN)
        print(local + " will be used for the LOCAL ASN...")
        local_asn = local
    elif 0 <= int(
            local) < 64512: # If selection is 'registered' the subsequent script will ask them to verify that they want to continue
        def registered_asn():
            global local_asn
            print("\n" +
                textwrap.fill("Again, keep in mind that " + local + " is a publicly registered number, and it may cause your VPN connection not to work unless you actually own the ASN. Are you certain you want to proceed (choose y/N)?", 80))
            print("--------------------------------------------------------------------------------")
            answer = raw_input("> ")
            if answer.lower() == 'yes' or answer.lower() == 'y':
                print(local + " will be used for the LOCAL ASN...")
                local_asn = local
            elif answer.lower() == 'no' or answer.lower() == 'n':
                local_as()
            else:
                print("\n" + "Please enter a valid answer 'yes' or 'no':")
                registered_asn()

        registered_asn()
    else:
        print("\n" +
            textwrap.fill("Invalid ASN: Number must be between 0 - 65536", 80) )
        local_as() # Will rerun script if invalid entry

# Asks for the private subnet behind the peer VPN device. This is the LAN private IP range on the remote side.
def remote_subnet():
    print(textwrap.fill("The REMOTE private network is currently specified as " + str(os.environ['REMOTE_LAN']) + ". Is this correct (choose y/N): ", 80))
    print("--------------------------------------------------------------------------------")
    remote_answer = raw_input("> ")
    if remote_answer.lower() == 'y' or remote_answer.lower() == "yes":
        global remote_sub
        remote_sub = str(os.environ['REMOTE_LAN'])
        print(str(os.environ['REMOTE_LAN']) + " is the REMOTE LAN...")
    elif remote_answer.lower() == 'n' or remote_answer.lower() == 'no':
        def check_remote():
            global remote_sub
            print("Enter the private subnet/LAN behind the REMOTE peer. (ex. 192.168.0.0/16):")
            print("--------------------------------------------------------------------------------")
            remosub = raw_input("> ")
            if 10 <= len(
                    remosub) <= 18: # This just checks the length of the range they enter. Working on more sophisticated checking
                print("{0} is the LAN behind the remote peer...".format(str(remosub)))
                remote_sub = remosub
            else:
                print("Invalid network: Please enter a network in the format of x.x.x.x/x")
                check_remote()
        check_remote()
    else:
        print("Invalid entry: Please try again")
        remote_subnet()

# Asks user if they want us to generate psk or if they want to use their own
def preshared_keys():
    global psk
    print("\n" + "Do you want CloudFort to generate a random preshared key for you (choose y/N):")
    print("--------------------------------------------------------------------------------")
    preshared = raw_input("> ")
    if preshared.lower() == 'y' or preshared.lower() == 'yes':
        myrg = random.SystemRandom()
        alphabet = string.ascii_letters + string.digits + string.punctuation
        psk = str().join(myrg.choice(alphabet) for _ in range(20)) # algorithm used to generate psk
        print("\n" + " " + str(psk) + " <----- will be used the preshared key for this connection")
    elif preshared.lower() == 'n' or preshared.lower() == 'no':
        print("\n" +
            textwrap.fill("Please enter the preshared key you want to use (make sure there are no leading or trailing spaces. You certainly want to use a mix of uppercase, lowercase, digits, and special characters - a preshared key length of 20 characters is recommended !):", 80))
        print("--------------------------------------------------------------------------------")
        psk = str(raw_input("> "))
        print("\n" + " " + str(psk) + " <----- will be used the preshared key for this connection")
    else:
        print("\n" + "Error: Invalid choice")
        preshared_keys()

# Asks user if they want us to auto-create phase 1 proposal/encryption parameters for them or if they want to manually do this
def phase_one_prop():
    global encryption_algorithm
    global hash_algorithm
    global dh_group
    global pfs_group
    global p2_lifetime
    global p2_enc_alg
    print ("\n" +
        textwrap.fill("Now it's time to specify the parameters for the VPN's phase 1 & 2 proposals. Would you like CloudFort to automatically create the proposal specifications (recommended), or you do you want to manually enter these (advanced)? Please select 1 or 2: ",80))
    print("--------------------------------------------------------------------------------")
    print("1) automatically select encryption parameters (recommended)")
    print("2) manually select encryption parameters (advanced)")
    phase_1_choice = raw_input("> ")
    if phase_1_choice == '1': # Selecting auto will let us set the parameters for them
        encryption_algorithm = "aes128"
        hash_algorithm = "sha1"
        dh_group = "2"
        pfs_group = '2'
        p2_lifetime = '3600'
        p2_enc_alg = 'aes128'

    elif phase_1_choice == '2': # Subsequent script allows user to manually enter their selections
        def p1_alg_question():
            global encryption_algorithm
            print(
                "\n" + "Please select one of the choices for the encryption algorithm you wish to use for phase 1/IKE (choose option 1 - 6): ")
            print("--------------------------------------------------------------------------------")
            print("1) aes128")
            print("2) aes256")
            print("3) des")
            print("4) 3des")
            print("5) rc5")
            print("6) blowfish")
            encrypt_alg = raw_input("> ")
            if encrypt_alg in ['1', '2', '3', '4', '5', '6']:
                p1_dictionary = {'1': 'aes128', '2': 'aes256', '3': 'des', '4': '3des', '5': 'rc5', '6': 'blowfish'}
                print( str(p1_dictionary[encrypt_alg]) + " will be used for phase 1 encryption algorithm...")
                encryption_algorithm = str(p1_dictionary[encrypt_alg])
            else:
                print("\n" + "Error: Invalid choice")
                p1_alg_question()

        def p1_hash_question():
            global hash_algorithm
            print("\n" + "Please specify the hash algorithm that you want to use (choose option 1 or 2): ")
            print("--------------------------------------------------------------------------------")
            print("1) SHA1")
            print("2) MD5")
            hash_alg = raw_input("> ")
            if hash_alg in ['1', '2']:
                p1_hash_dict = {'1': 'sha1', '2': 'md5'}
                print(p1_hash_dict[hash_alg] + " will be used for phase 1 hash algorithm...")
                hash_algorithm = str(p1_hash_dict[hash_alg])
            else:
                print("\n" + "Error: Invalid choice")
                p1_hash_question()

        def p1_dh_group():
            global dh_group
            print("\n" + "Please enter the DH group number for phase 1/IKE of this connection (choose option 1 - 3): ")
            print("--------------------------------------------------------------------------------")
            print("1) DH group 1")
            print("2) DH group 2")
            print("3) DH group 5")
            dh_group_choice = raw_input("> ")
            if dh_group_choice in ['1', '2', '3']:
                dh_selection = {'1':'1','2':'2','3':'5'}
                print("dhgroup " + dh_selection[dh_group_choice] + " will be used for the DH group...")
                dh_group = str(dh_selection[dh_group_choice])
            else:
                print("\n" + "Error: Invalid choice")
                p1_dh_group()

        def pfs_checker():
            global pfs_group
            print("\n" + "What PFS DH group do you want to use for phase 2? ")
            print("--------------------------------------------------------------------------------")
            print("1) PFS dhgroup 1 ")
            print("2) PFS dhgroup 2 ")
            print("3) PFS dhgroup 5 ")
            phase2_question = raw_input("> ")
            if phase2_question in ['1', '2', '3']:
                p2_final_answer = {'1': '1', '2': '2', '3': '5'}
                print("PFS dhgroup " + p2_final_answer[phase2_question] + " is selected...")
                pfs_group = str(p2_final_answer[phase2_question])
            else:
                print("\n" + "Invalid entry: Please try again")
                pfs_checker()

        def p2_lifetime_checker():
            global p2_lifetime
            print(
                "\n" + "What is the lifetime in seconds that you want to use for phase 2? For example 3600 is 5 minutes: ")
            print("--------------------------------------------------------------------------------")
            lifetime = raw_input("> ")
            if lifetime.isdigit():
                print(lifetime + " will be used for phase 2 lifetime...")
                p2_lifetime = str(lifetime)
            else:
                print("\n" + "Invalid Entry: Please enter a numeric value for the lifetime...")
                p2_lifetime_checker()

        def p2_enc_checker():
            global p2_enc_alg
            print(
                "\n" + textwrap.fill("What is the encryption algorithm that you want to use for phase 2? Please choose from an option from below (choose option 1 - 8):", 80))
            print("--------------------------------------------------------------------------------")
            print("1) aes128")
            print("2) aes256")
            print("3) des")
            print("4) 3des")
            print("5) cast")
            print("6) blowfish")
            print("7) twofish")
            print("8) rijndael")
            enc_check_answer = raw_input("> ")
            if 0 < int(enc_check_answer) < 9:
                enc_check_final_answer = {'1': 'aes128', '2': 'aes256', '3': 'des', '4': '3des', '5': 'cast',
                                          '6': 'blowfish', '7': 'twofish', '8': 'rijndael'}
                print(
                    enc_check_final_answer[
                        enc_check_answer] + " will be used for the encryption algorithm of phase 2...")
                p2_enc_alg = str(enc_check_final_answer[enc_check_answer])
            else:
                print("\n" + "Invalid entry: Please try again")
                p2_enc_checker()


        p1_alg_question()
        p1_hash_question()
        p1_dh_group()
        pfs_checker()
        p2_lifetime_checker()
        p2_enc_checker()
    else:
        print("\n" + "Error: Invalid choice")
        phase_one_prop()

def nat(): # Asks if they want to turn server into NAT server as well
    print("\n" + textwrap.fill("Would you like for CloudFort to turn this server into a NAT server for your private EC2 instances as well (Y/n)? ", 80))
    nat_answer = raw_input("> ")
    if nat_answer.lower() == 'y' or nat_answer.lower() == 'yes':
        clioutput("iptables --table nat --append POSTROUTING --source " + str(os.environ['LOCAL_LAN']) + " -j MASQUERADE")
    elif nat_answer.lower() == 'n' or nat_answer.lower() == 'no':
        return
    else:
        print("\n" + "Invalid entry: Please choose 'Y' or 'N'"+"\n")
        nat()

# Prints summary output
def summary():
    print("\n Here is a summary of your configuration. This has also been emailed to " + str(os.environ['EMAIL']) + "\n")

    print("======================================================")
    print(" Phase 1 Proposal ")
    print("======================================================" + "\n")
    print("Local public IP: " + local_public_ip)
    print("Peer public IP: " + peer_public_ip)
    print("Preshared Key: " + "\"" + psk + "\"" + " <-- Please DO NOT include the end quotations in your preshared key" )
    print("Encryption: " + encryption_algorithm + ", " + hash_algorithm + ", " + "dhgroup " + dh_group + "\n")

    print("======================================================")
    print(" Phase 2 Proposal ")
    print("======================================================")
    print("Local Private LAN: " + local_sub)
    print("Remote Private LAN: " + remote_sub)
    print("Encryption: " + "pfs group " + pfs_group + ", " + p2_enc_alg)
    print("SA Lifetime: " + p2_lifetime + "\n")

    print("======================================================")
    print(" BGP Configuration ")
    print("======================================================")
    print("Remote Tunnel IP: " + remote_tunnel_ip)
    print("Local Tunnel IP: " + local_tunnel_ip)
    print("Peers ASN: " + peers_asn)
    print("Local ASN: " + local_asn + "\n")

# Sends email via SNS
def send_email(): # Sends an email with config parameters to the email that the customer specified
    os.system("echo ============================== >> message.json")
    os.system("echo ' Phase 1 Proposal ' >> message.json")
    os.system("echo ============================== >> message.json")
    os.system("echo Local Public IP: " + peer_public_ip + " >> message.json")
    os.system("echo Peer Public IP: " + local_public_ip + " >> message.json")
    os.system("echo 'Preshared Key: " + "\"" + str(
        psk) + "\"" + " <-- Please *DO NOT* include the *END* quotations in your preshared key' >> message.json")
    os.system("echo Encryption: " + encryption_algorithm + ", " + hash_algorithm + ", " + "dhgroup " + dh_group + " >> message.json")
    os.system("echo ============================== >> message.json")
    os.system("echo ' Phase 2 Proposal ' >> message.json")
    os.system("echo ============================== >> message.json")
    os.system("echo Local Private LAN: " + remote_sub + " >> message.json")
    os.system("echo Remote Private LAN: " + local_sub + " >> message.json")
    os.system("echo Encryption: pfs group " + pfs_group + ", " + p2_enc_alg + " >> message.json")
    os.system("echo SA lifetime: " + p2_lifetime + " >> message.json")
    os.system("echo ============================== >> message.json")
    os.system("echo ' BGP Configuration ' >> message.json")
    os.system("echo ============================== >> message.json")
    os.system("echo Remote Tunnel IP: " + local_tunnel_ip + " >> message.json")
    os.system("echo Local Tunnel IP: " + remote_tunnel_ip + " >> message.json")
    os.system("echo Peers ASN: " + local_asn + " >> message.json")
    os.system("echo Local ASN: " + peers_asn + " >> message.json")
    time.sleep(1)
    os.system("aws sns publish --topic-arn $SNS --message file://message.json --subject 'Connection config for " + str(os.popen("curl -s http://169.254.169.254/latest/meta-data/public-ipv4").read() + "' --region " + region))
    os.system("rm message.json")

#Creates template files
def templatecreate():
    global daemonstemplate
    global bgpdtemplate
    global ipsectemplate
    global psktemplate
    global racoontemplate
    global zebratemplate
    global daemonstemplate
    global eth0template
    global sysctltemplate
    #Template for files to write

    sysctltemplate = """#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0
net.ipv4.conf.lo.rp_filter=0

net.ipv4.ip_forward=1
"""

    eth0template = """# The primary network interface
auto eth0
iface eth0 inet dhcp
post-up ip a a """ + local_tunnel_ip + " dev eth0"

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

<PEER PUBLIC IP> <PSK>
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

#Modifies sytem files and permissions
def modifysysfiles():
    #Used to open and write files
    def findandreplace(filename, replacement, template):

        #Open file, split into a list
        file = open(filename, "w+")
        file.truncate()
        for src, target in replacement.iteritems():
            template = template.replace(src, target)
        file.write(template)
        file.close()
        return True

    #Write config files
    findandreplace("/etc/quagga/bgpd.conf", {"<LOCAL ASN>":local_asn, "<LOCAL PUBLIC IP>":local_public_ip, "<LOCAL TUNNEL IP>":local_tunnel_ip, "<LOCAL SUB>":local_sub, "<REMOTE TUNNEL IP>":remote_tunnel_ip.split("/", 1)[0], "<REMOTE ASN>":peers_asn}, bgpdtemplate)
    findandreplace("/etc/ipsec-tools.conf", {"<LOCAL TUNNEL IP>":local_tunnel_ip, "<REMOTE TUNNEL IP>":remote_tunnel_ip, "<REMOTE SUB>":remote_sub, "<LOCAL SUB>":local_sub, "<LOCAL PRIVATE IP>":local_private_ip, "<PEER PUBLIC IP>":peer_public_ip}, ipsectemplate)
    findandreplace("/etc/racoon/psk.txt", {"<PEER PUBLIC IP>":peer_public_ip, "<PSK>":psk}, psktemplate)
    findandreplace("/etc/racoon/racoon.conf", {"<PEER PUBLIC IP>":peer_public_ip, "<LOCAL PUBLIC IP>":local_public_ip, "<ENCRYPTION ALGORITHM>":encryption_algorithm, "<HASH ALGORITHM>":hash_algorithm, "<DH GROUP>":dh_group, "<LOCAL TUNNEL IP>":local_tunnel_ip, "<REMOTE TUNNEL IP>":remote_tunnel_ip, "<PFS GROUP>":pfs_group, "<P2 LIFETIME>":p2_lifetime, "<P2 ENC ALG>":p2_enc_alg}, racoontemplate)
    findandreplace("/etc/quagga/zebra.conf", {}, zebratemplate)
    findandreplace("/etc/quagga/daemons", {}, daemonstemplate)
    findandreplace("/etc/network/interfaces.d/eth0.cfg", {}, eth0template)
    findandreplace("/etc/sysctl.conf", {}, sysctltemplate)

    #chmod for required files
    clioutput("chmod 600 /etc/racoon/psk.txt")
    clioutput("chmod 600 /etc/racoon/racoon.conf")

    #add ip address, import config from sysctl.conf, add programs to boot on restart
    clioutput("ip a a " + local_tunnel_ip + " dev eth0")
    clioutput("sudo sysctl -p")
    clioutput("sudo update-rc.d quagga defaults")
    clioutput("sudo update-rc.d setkey defaults")
    clioutput("sudo update-rc.d racoon defaults")


#Variable Declaration
local_private_ip = str(os.popen("""/sbin/ifconfig eth0|grep inet|awk {'print $2'}|cut -d":" -f2""").read()).strip()
local_public_ip = str(os.popen("curl -s http://169.254.169.254/latest/meta-data/public-ipv4").read())
local_sub = str(os.environ['LOCAL_LAN'])
remote_sub = str(os.environ['REMOTE_LAN'])


#Initial Welcome Text
print("================================================================================")
print(
    textwrap.fill("Thank you for using CloudFort. This interface will take you through the process of setting an IPSEC VPN connection from this server to your remote peer.",80))
print("================================================================================")

#Calling functions
print("\n")
subscription()
peers_public()
print("\n")
peer_tunnel()
print("\n")
local_as()
print("\n")
peers_as()
print("\n")
preshared_keys()
print("\n")
phase_one_prop()
print("\n")
nat()
print("\n")
templatecreate()

# Changing Security Groups to open needed ports for IKE/IPSEC, and other communications.
sg_id = str(os.environ['PUBLIC_SG'])
region = str(os.popen("ec2-metadata -z | grep -Po '(us|sa|eu|ap)-(north|south)?(east|west)?-[0-9]+'").read())
print("\n\nFinishing up. This may take a few minutes...")

# Security Group commands
clioutput("aws ec2 authorize-security-group-ingress --group-id " + sg_id + " --protocol 51 --cidr " + str(peer_public_ip) + "/32 --region " + region)
clioutput("aws ec2 authorize-security-group-ingress --group-id " + sg_id + " --protocol 50 --cidr " + str(peer_public_ip) + "/32 --region " + region)
clioutput("aws ec2 authorize-security-group-ingress --group-id " + sg_id + " --protocol udp --port 500 --cidr " + str(peer_public_ip) + "/32 --region " + region)
clioutput("aws ec2 authorize-security-group-ingress --group-id " + sg_id + " --protocol udp --port 4500 --cidr " + str(peer_public_ip) + "/32 --region " + region)

#Sends email
send_email()
# os.system("clear") <---may want to uncomment this later

#Modify tunnel IPs to include subnets
local_tunnel_ip = local_tunnel_ip + "/30"
remote_tunnel_ip = remote_tunnel_ip + "/30"

#Modifies system files
try:
    modifysysfiles()
except:
    print "--ERROR:\nFailed to modify files and permissions, please make sure you are running this script as root.\n"
    sys.exit(1)

#stop/start required services
clioutput("service racoon stop")
time.sleep(1)
clioutput("service quagga restart")
time.sleep(2)
clioutput("service setkey restart")
clioutput("service racoon start")
time.sleep(1)
clioutput("racoonctl vpn-connect " + peer_public_ip)

#Summarize Changes
os.system("clear")
summary()