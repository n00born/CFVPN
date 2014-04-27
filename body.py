__author__ = 'Ben_Normal_User'
import string
import socket
from numbers import Number
import random
import re
import textwrap

print(
    textwrap.fill("Thank you for using ZPN. This interface will take you through the process of setting an IPSEC VPN connection from this server to your remote peer(s).",80))


# This function will be used below to validate IPs (this may need some working on)
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

# Function that asks user for the VPN peer's public IP
def peers_public():
    global peer_public_ip
    print("\n" +
        textwrap.fill("Please enter the public IP of the remote peer that you want to establish an IPSEC VPN connection with (must be in format x.x.x.x):",80))
    peer = raw_input("> ")
    if ipFormatChk(peer): # runs ip check before passing it into variable
        print(peer + " will be used for the peer's public IP...")
        peer_public_ip = peer
        assert isinstance(peer_public_ip, object)
        return peer_public_ip
    else:
        print("Invalid entry: Please enter the remote peer's public IP in a valid format")
        peers_public() # reruns the same function if invalid answer


# This function will be used to ask user for remote side's tunnel IP.
def peer_tunnel():
    global remote_tunnel_ip
    print(
        "\n" + textwrap.fill("Do you want to specify the tunnel IP of the REMOTE peer or do you want ZPN to generate this for your peer (IP must be within 169.254.251.x range)? Please select option 'A' or 'B':", 80))
    print("A) generate tunnel IP for the REMOTE peer")
    print("B) I know the REMOTE peer's tunnel IP, and want to specify it")
    tunnel_ip_answer = raw_input("> ")
    if tunnel_ip_answer.lower() == 'b':
        def remote_ip():
            global remote_tunnel_ip
            print(
                "\n" + textwrap.fill("What tunnel IP will the remote peer be using for the connection to this VPN gateway? (remember that it must be 169.254.251.x):",80))
            tunnel_ip = raw_input("> ")

            def extractIP(ipStr):
                l = re.split('(.*)\.(.*)\.(.*)\.(.*)',
                             ipStr) # function will be used to parse and check that user input is in 169.254.251.x range
                return l[1:-1]

            if ipFormatChk(tunnel_ip) and 254 >= int(extractIP(tunnel_ip)[3]) > 0 and int(
                    extractIP(tunnel_ip)[0]) == 169 and int(
                    extractIP(tunnel_ip)[1]) == 254 and int(extractIP(tunnel_ip)[2]) == 251:
                print(str(tunnel_ip) + " will be used for the remote tunnel IP...")
                remote_tunnel_ip = tunnel_ip
            else:
                print("Invalid entry")
                remote_ip()

        remote_ip()
    elif tunnel_ip_answer.lower() == 'a': # If user chooses 'a' then a random IP is generated
        global remote_tunnel_ip
        final_peer = ["169.254.251", str(random.randint(1, 254))]
        remote_tunnel_ip = ".".join(final_peer)
        print(remote_tunnel_ip + " will be used for the remote tunnel IP of this connection...")
    else:
        print("Invalid entry")
        peer_tunnel()


# This function will ask user what tunnel IP they want to use on the LOCAL side, and if they want to manually enter it or let ZPN generate it.
def local_tunnel():
    global local_tunnel_ip
    print(
        "\n" + textwrap.fill( "Do you want ZPN to generate the LOCAL tunnel IP, or do you want to specify it (Must be in 169.254.251.x range)? Please select option 'A' or 'B': ", 80))
    print("A) generate LOCAL tunnel IP to use")
    print("B) I will choose the LOCAL tunnel IP")
    tunnel_ip_answer = raw_input("> ")
    if tunnel_ip_answer.lower() == 'b':
        def local_ip():
            global local_tunnel_ip
            print(
                "\n" + textwrap.fill("What tunnel IP do you want to use for the LOCAL side of this connection (remember it must be 169.254.251.x)", 80))
            tunnel_ip = raw_input("> ")

            def extractIP(ipStr):
                l = re.split('(.*)\.(.*)\.(.*)\.(.*)',
                             ipStr) # function will be used to parse and check that user input is in 169.254.251.x range
                return l[1:-1]
            if ipFormatChk(tunnel_ip) and 254 >= int(extractIP(tunnel_ip)[3]) > 0 and int(
                    extractIP(tunnel_ip)[0]) == 169 and int(extractIP(tunnel_ip)[1]) == 254 and int(
                    extractIP(tunnel_ip)[2]) == 251 and int(extractIP(tunnel_ip)[3]) != int(extractIP(remote_tunnel_ip)[3]):
                print(str(tunnel_ip) + " will be used for the LOCAL tunnel IP...")
                local_tunnel_ip = extractIP(tunnel_ip)
            else:
                print("Invalid entry: Please be sure the IP is valid and not the same as the remote IP")
                local_ip()

        local_ip()
    elif tunnel_ip_answer.lower() == 'a': # If user chooses 'a' then a random IP is generated
        global remote_tunnel_ip
        final = ["169.254.251", str(random.randint(1, 254))]
        local_tunnel_ip = ".".join(final)
        print(local_tunnel_ip + " will be used for the remote tunnel IP of this connection...")

    else:
        print("Invalid entry")
        local_tunnel()


# Asks user for peer BGP ASN
def peers_as():
    global peers_asn
    print("Enter the BGP ASN of the REMOTE peer you are connecting to (ex.'65030'):")
    peer = raw_input("> ")
    if 65536 >= int(peer) >= 0: # Verifies that the ASN is between 0 - 65536 (valid)
        print(peer + " will be used for the REMOTE peer's ASN...")
        peers_asn = peer
    else:
        print("Invalid entry: Please enter an ASN between 0-65536")
        peers_as() # Reruns function if answer is invalid

# This function asks user what ASN they want, and checks to make sure it is valid
def local_as():
    global local_asn
    print(
        textwrap.fill("Enter the BGP ASN of this LOCAL server.(NOTE: you must choose something between 65000 - 65536. Anything less than 65000 should be publicly registered to you):", 80))
    local = raw_input("> ")
    if 65000 <= int(
            local) <= 65536 and local != peers_asn: # Checking to make sure ASN selected is above 65000 (so that it is not a registered ASN)
        print(local + " will be used for the LOCAL ASN...")
        local_asn = int(local)
    elif 0 <= int(
            local) < 65000 and local != peers_asn: # If selection is 'registered' the subsequent script will ask them to verify that they want to continue
        def registered_asn():
            global local_asn
            print(
                textwrap.fill("Again, keep in mind that " + local + " is a publicly registered number, and it may cause your VPN connection not to work unless you actually own the ASN. Are you certain you want to proceed (choose 'yes' or 'no')?", 80))
            answer = raw_input("> ")
            if answer.lower() == 'yes' or answer.lower() == 'y':
                print(local + " will be used for the LOCAL ASN...")
                local_asn = int(local)
            elif answer.lower() == 'no' or answer.lower() == 'n':
                local_as()
            else:
                print("Please enter a valid answer 'yes' or 'no':")
                registered_asn()

        registered_asn()
    else:
        print(
            textwrap.fill("Invalid ASN: Number must be between 0 - 65536, and make sure it is not the number already used by your peer", 80) )
        local_as() # Will rerun script if invalid entry

# This function asks for the private subnet behind the peer VPN device. This is the LAN private IP range on the remote side.
def remote_subnet():
    global remote_sub
    print("Enter the private subnet/LAN behind the REMOTE peer. (ex. 192.168.0.0/16):")
    remosubnet = raw_input("> ")
    if 10 <= len(
            remosubnet) <= 18: # This just checks the length of the range they enter. Working on more sophisticated checking
        print("{0} is the LAN behind the remote peer...".format(str(remosubnet)))
        remote_sub = remosubnet
    else:
        print("Invalid network: Please enter a network in the format of x.x.x.x/x")
        remote_subnet()

# Asks user if they want us to generate psk or if they want to use their own
def preshared_keys():
    global psk
    print("Do you want ZPN to generate a random preshared key for you (choose 'y' or 'n'):")
    preshared = raw_input("> ")
    if preshared.lower() == 'y' or preshared.lower() == 'yes':
        myrg = random.SystemRandom()
        alphabet = string.ascii_letters + string.digits + string.punctuation
        psk = str().join(myrg.choice(alphabet) for _ in range(20)) # algorithm used to generate psk
        print("\n" + "  " + str(psk) + "   <----- will be used the preshared key for this connection")
    elif preshared.lower() == 'n' or preshared.lower() == 'no':
        print(
            textwrap.fill("Please enter the preshared key you want to use (make sure there are no leading or trailing spaces. You certainly want to use a mix of uppercase, lowercase, digits, and special characters - a preshared key length of 20 characters is recommended !):", 80))
        psk = raw_input("> ")
        print("\n" + "  " + str(psk) + "    <----- will be used the preshared key for this connection")
    else:
        print("Error: Invalid choice")
        preshared_keys()

# This asks user if they want us to auto-create phase 1 proposal/encryption parameters for them or if they want to manually do this
def phase_one_prop():
    global encryption_algorithm
    global hash_algorithm
    global dh_group
    print (
        textwrap.fill("Now it's time to specify the parameters for the VPN's phase 1 proposal. Would you like ZPN to automatically create the proposal specifications (recommended), or you do you want to manually enter these (advanced)? Please select 'A' or 'B': ",80))
    print("A) automatically select phase 1 encryption parameters (recommended)")
    print("B) manually select phase 1 encryption parameters (advanced)")
    phase_1_choice = raw_input("> ")
    if phase_1_choice.lower() == 'a': # Selecting auto will let us set the parameters for them
        encryption_algorithm = "aes256"
        hash_algorithm = "sha1"
        dh_group = "2"
        print( textwrap.fill("ZPN will automatically choose phase 1 encryption parameters. These will be shown in the summary at the end...", 80))

    elif phase_1_choice.lower() == 'b': # Subsequent script allows user to manually enter their selections
        def p1_alg_question():
            global encryption_algorithm
            print(
                "\n" + "Please select one of the choices for the encryption algorithm you wish to use (choose 'A - F'): ")
            print("A) aes128")
            print("B) aes256")
            print("C) des")
            print("D) 3des")
            print("E) rc5")
            print("F) blowfish")
            encrypt_alg = raw_input("> ")
            if encrypt_alg.lower() in ['a', 'b', 'c', 'd', 'e', 'f']:
                p1_dictionary = {'a': 'aes128', 'b': 'aes256', 'c': 'des', 'd': '3des', 'e': 'rc5', 'f': 'blowfish'}
                print( str(p1_dictionary[encrypt_alg]) + " will be used for phase 1 encryption algorithm...")
                encryption_algorithm = p1_dictionary[encrypt_alg]
            else:
                print("Error: Invalid choice")
                p1_alg_question()

        def p1_hash_question():
            global hash_algorithm
            print("\n" + "Please specify the hash algorithm that you want to use (choices are 'A' or 'B'): ")
            print("A) SHA1")
            print("B) MD5")
            hash_alg = raw_input("> ")
            if hash_alg.lower() in ['a', 'b']:
                p1_hash_dict = {'a': 'sha1', 'b': 'md5'}
                print(p1_hash_dict[hash_alg] + " will be used for phase 1 hash algorithm...")
                hash_algorithm = p1_hash_dict[hash_alg]
            else:
                print("Error: Invalid choice")
                p1_hash_question()

        def p1_dh_group():
            global dh_group
            print("\n" + "Please enter the DH group number for phase 1 of this connection (choices are '1','2', or '5': ")
            dh_group_choice = raw_input("> ")
            if dh_group_choice in ['1', '2', '5']:
                print("dhgroup " + dh_group_choice + " will be used for the DH group...")
                dh_group = dh_group_choice
            else:
                print("Error: Invalid choice")
                p1_dh_group()


        p1_alg_question()
        p1_hash_question()
        p1_dh_group()
    else:
        print("Error: Invalid choice")
        phase_one_prop()


# Below is a function that checks whether the user wants to have his phase 2 parameters auto generated or not.
def phase_two_prop():
    global pfs_group
    global p2_lifetime
    global p2_enc_alg
    print(
        "\n" + textwrap.fill("Would you like ZPN to automatically set phase 2 encryption parameters for you, or do you want to do this manually? Please choose 'A' or 'B': ",80))
    print("A) Auto (recommended)")
    print("B) I want to manually set my own parameters")
    p2_check = raw_input("> ")

    if p2_check.lower() == 'a':
        pfs_group = '2'
        p2_lifetime = '3600'
        p2_enc_alg = 'aes128'

    elif p2_check.lower() == 'b':
        def pfs_checker():
            global pfs_group
            print("\n" + "What PFS DH group do you want to use for phase 2? ")
            print("A) PFS dhgroup 1 ")
            print("B) PFS dhgroup 2 ")
            print("C) PFS dhgroup 5 ")
            phase2_question = raw_input("> ")
            if phase2_question.lower() in ['a', 'b', 'c']:
                p2_final_answer = {'a': '1', 'b': '2', 'c': '5'}
                print("PFS dhgroup " + p2_final_answer[phase2_question] + " is selected...")
                pfs_group = str(p2_final_answer[phase2_question])
            else:
                print("Invalid entry: Please try again")
                pfs_checker()

        def p2_lifetime_checker():
            global p2_lifetime
            print(
                "\n" + "What is the lifetime in seconds that you want to use for phase 2? For example 3600 is 5 minutes: ")
            lifetime = raw_input("> ")
            if lifetime.isdigit():
                print(lifetime + " will be used for phase 2 lifetime...")
                p2_lifetime = lifetime
            else:
                print("Invalid Entry: Please enter a numeric value for the lifetime...")
                p2_lifetime_checker()

        def p2_enc_checker():
            global p2_enc_alg
            print(
                "\n" + textwrap.fill("What is the encryption algorithm that you want to use for phase 2? Please choose from an option from below:", 80))
            print("A) aes128")
            print("B) aes256")
            print("C) des")
            print("D) 3des")
            print("E) cast")
            print("F) blowfish")
            print("G) twofish")
            print("H) rijndael")
            print("I) null")
            enc_check_answer = raw_input("> ")
            if enc_check_answer in list(string.ascii_lowercase):
                enc_check_final_answer = {'a': 'aes128', 'b': 'aes256', 'c': 'des', 'd': '3des', 'e': 'cast',
                                          'f': 'blowfish', 'g': 'twofish', 'h': 'rijndael', 'i': 'null'}
                print(
                    enc_check_final_answer[
                        enc_check_answer] + " will be used for the encryption algorithm of phase 2...")
                p2_enc_alg = enc_check_final_answer[enc_check_answer]
            else:
                print("Invalid entry: Please try again")
                p2_enc_checker()

        pfs_checker()
        p2_lifetime_checker()
        p2_enc_checker()

    else:
        print("Invalid entry: Please try again")
        phase_two_prop()


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
    print("Remote Tunnel IP: " + remote_tunnel_ip)
    print("Local Tunnel IP: " + local_tunnel_ip)
    print("Peers ASN: " + str(peers_asn))
    print("Local ASN: " + str(local_asn) + "\n")


peers_public()
print("\n")
peer_tunnel()
print("\n")
local_tunnel()
print("\n")
peers_as()
print("\n")
local_as()
print("\n")
remote_subnet()
print("\n")
preshared_keys()
print("\n")
phase_one_prop()
print("\n")
phase_two_prop()
print("\n")
summary()
