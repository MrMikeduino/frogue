# Frogue
Security Tool

Description
-----------
The frogue is a very handy network security tool for identifying rogue
(unauthorized) DHCP servers. Compares against a list of known given
authorized DHCP servers in CSV file format to eliminate false positives.

Author:    M.Guman  
Baselined: 20220312

Notes:
------
You must set the network _interface variable to the description of your 
interface when running under Windows OS. This can be found in your
network adapters properties by either the GUI or by executing an
'ipconfig /all' command.

Also, you must provide a text file (even if blank) of authorized
DHCP servers in CSV format.  A sample file named 'Auth.txt' is 
provided as an example. 



Requirements:
-------------
- Python3
- scapy package 
- colorama package
- csv package (should be included inbuilt with python3)
- text file of authorized servers (can be blank if need be)
          

Syntax:
------- 
python3 frogue.py -i <authorized_servers_file> -o <output_filename>



Steps:
------
1) Create a text file (use auth.txt) as a template, can be blank
2) python3 frogue.py -i auth.txt -o red_list.txt


Enjoy!
