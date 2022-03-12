#! /usr/bin/env python3
#######################################################################
#
# frogue - Simple but handy network security tool for identifying rogue
#          (unauthorized) DHCP servers. Compares against a known given
#          authorized DHCP server CSV file to eliminate false positives.
#
#          Note!: You must set the network _interface below. 
#                See Readme for details on how to do properly find and
#                do this, especially when running under Windows OS.
#
#
# Author: M.Guman
#
# History:  20220312 Baselined 
#           
# External Dependencies:     scapy (pip3 install scapy)
#                            colorama (pip3 install colorama)
# 
#######################################################################
import os
import sys
import csv
import getopt
import argparse
import datetime
#import logging

# Change this below, obtain from description of network interface
# See readme for details
#
_interface="Intel(R) 82579LM Gigabit Network Connection"

def print_syntax():
    print ("\n-------------------------------------------------------------------------")
    print ("rogue.py - Simple but handy security tool for finding and identifying rogue ")
    print ("           (unauthorized) DHCP servers.\n")
    print ("Syntax: python3 frogue.py -i <authorized_server_file> -o <redlist_output>\n")
    

    print ("Note: Authorized DHCP server file is CSV format  (Name,ipv4_address)")
    print ("      Requires scapy package, use (pip3 install scapy) to install.")
    print ("      Requires colorama package, use (pip3 install colorama) to install.")
    print ("-------------------------------------------------------------------------")
 
# Check for required libraries 
#
try:
    from scapy.all import *
except ImportError:
    print("Please install scapy on your system.\n")   
    print_syntax()
    sys.exit()
try:
    import colorama
except ImportError:
    print("Please install colorama on your system.\n")   
    print_syntax()
    sys.exit()   
#   
_rogue_dhcp_servers = {}
_authorized_servers ={}

CLEAR_SCREEN = '\033[2J'
RED = '\033[31m'   # mode 31 = red forground
REDB = '\033[41m'  # mode 41 = red background
GREEN = '\033[32m' # mode 42 = green forground
RESET = '\033[0m'  # mode 0  = reset
print(CLEAR_SCREEN + GREEN + 'Scanning for rogue DHCP servers.....' + RESET)


def load_authorized_servers(ccFileName):
    """ Loads a list of CSV authorized servers """
    if not os.path.exists(ccFileName):
       print ("Could not load authorized server list.")
    else:   
        with open(ccFileName, 'r') as csvDataFile:
            csvReader = csv.reader(csvDataFile)
            for row in csvReader:
                if len(row) >= 2:
                    entry = row
                    try:
                        _authorized_servers[entry[1]] = entry[0]
                    except:
                        print("File format error:" + entry[0] + ":" +entry[1])

def scan_for_rogue_rogue_dhcp_servers():
    """ scans for all DHCP servers and adds to a list""" 
    #    
    # Get hardware address
    #
    try:
        info, mac = get_if_raw_hwaddr(_interface)
    except: 
        print(REDB + "Could not find given network adapter:\n {} ".format(_interface)) 
        print("This needs to be defined in code on line 31, see readme for more detail.")        
        sys.exit() 
    #    
    # Create the DHCP discovery packet
    #   
    e = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    ip = IP(src = '0.0.0.0', dst = '255.255.255.255')
    udp = UDP (sport = 68, dport = 67)
    bootp = BOOTP(chaddr = mac)
    dhcp = DHCP(options = [('message-type', 'discover'), 'end'])
    dhcp_packet = e/ip/udp/bootp/dhcp
    #
    conf.checkIPaddr = False  # Disable making sure replies come from same IP address sent to
    ans, unans = srp(dhcp_packet, multi=True, iface=_interface, timeout=15)
    results = {}  # Store IP address and MAC address in results
    
    for tup in ans:
        results[tup[1][Ether].src] = tup[1][IP].src  # DHCP server should report its source address
    # Check if we snagged any
    if ans:
        print("Found some DHCP servers on the {} network interface: \n".format(_interface))

        for mac, ip in results.items():
            if ip in _authorized_servers:
                print( GREEN +"Normal IP Address : {}, with MAC Address : {}\n".format(ip,mac))
            else:
                print( RED + "Possible ROGUE Server found at IP Address : {}, with MAC: {} \n".format(ip,mac))
                # add to redlist
                _rogue_dhcp_servers[mac]=ip               
    else:
        print(RED+ "\n No DHCP servers were found on the {} interface\n".format(_interface))         
    #    
    print(RESET)
 
def save_redlist(redfilename):
    """ Writes rogues to the prescribed output file in CSV """
    print ("\nSummary IP Red List of possible rogue DHCP servers:")
    print ("-----------------------------------------------")
    # dump to red list file
    with open(redfilename, 'w') as f:
        for mac, ip in _rogue_dhcp_servers.items():
            print(ip+"---"+mac)
            f.write(ip + "," + mac)
    
def main(argv):
    try:     
        opts, args = getopt.getopt(argv,"hi:o:")           
    except getopt.GetoptError:
        print_syntax()
        sys.exit(2)
        
    # Validate args  
    if len(opts) != 2:
        print_syntax()
        sys.exit(2) 
        
    # Parse arguments
    for opt, arg in opts:
        #help
        if opt == '-h':
            print_syntax()
            sys.exit()
        elif opt in ("-i", "--input"):
            inputFile = arg
        elif opt in ("-o", "--output"):
            redFileNameOutput = arg
        
    if not os.path.exists(inputFile):
        print("Authorized DHCP file: {} does not exist!".format(inputFile))
        print_syntax()
        sys.exit(2)    
    else:
        start = datetime.now()  
        print ("Processing....please wait at least 15 seconds for scan to complete.\n\n")       
        load_authorized_servers(inputFile)
        scan_for_rogue_rogue_dhcp_servers()
        save_redlist(redFileNameOutput)
        end = datetime.now()
        print("\nTotal scan execution time: {}".format(end - start))

if __name__ == "__main__":
    main(sys.argv[1:])
    print("Complete.")
    exit(0)

