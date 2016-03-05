#! /usr/bin/python

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

#uses scapy to conduct an ICMP ping of the target. If it gets a reply then it returns true.
def alive(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=3, verbose=False)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True

#takes a string of ports entered by the user and expands ranges, converts to ints, and orders them.
def portOrganizer(ports):
    organized = []
    for port in ports:
        if "-" in port:
            split = re.split(r'\s|-', port)
            r = list(range(int(split[0]), (int(split[1])+1)))
            organized.extend(r)
        else:
            organized.append(port)
    organized = list(map(int,organized))
    organized = list(set(organized))
    organized.sort()
    return organized

#uses scapy to perform a traceroute using 
def tr(ip):
    print
    print("=======Traceroute=======")
    result, unans = traceroute(ip, maxttl=5, verbose=False)
    result.show()

#uses scapy to conduct a tcp port scan.
def TCPscan(ip, port, src_port):
    tcp_connect_scan_resp = sr1(IP(dst=ip)/TCP(sport=src_port,dport=port,flags="S"),timeout=2, verbose=False)
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
        print("tcp/"+str(port) + " is closed")
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=ip)/TCP(sport=src_port,dport=port,flags="AR"),timeout=2, verbose=False)
            print("tcp/"+str(port) + " is open")
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            print("tcp/"+str(port) + " is closed")

#uses scapy to conduct a udp port scan
def UDPscan(ip, port):
    udp_scan_resp = sr1(IP(dst=ip)/UDP(dport=port),timeout=3, verbose=False)
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        print("udp/"+str(port) + " is open|filtered")
    elif (udp_scan_resp.haslayer(UDP)):
        print("udp/"+str(port) + " is open")
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            print("udp/"+str(port) + " is closed")
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            print("udp/"+str(port) + " is filtered")

#main program logic
def main():
    #using argparse for options and help
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--targets", nargs="*", help="Input target/s ip address seperated by a space. Example: 192.168.1.1 192.168.1.2")
    parser.add_argument("-p", "--ports", nargs="*", help="input port/s seperated by a space. You may enter a range as well Example: 1 2 3-8 9 10")
    parser.add_argument("-u", "--udp", dest="u", action="store_true", help="Runs a udp scan against all specified ports")
    parser.add_argument("-tr", "--trace", dest="tr", action="store_true", help="Runs a traceroute on all target hosts using ICMP")
    args = parser.parse_args()

    #calls portOrganizer method and returns a list of ints
    ports = portOrganizer(args.ports)

    #iterates through each of the user specified targets
    for target in args.targets:
        #calls the alive method to test if host is up
        if alive(target):
            print("====== Results for " + target + " ======")
            print
            for port in ports:
                src_port = RandShort()
                TCPscan(target, port, src_port)

            #checks option for udp scan
            if args.u == True:
                for port in ports:
                    UDPscan(target, port)

        #if not alive then go here and print host is down
        else:
            print("====== Results for " + target + " ======")
            print
            print("host is down")

        #traceroute
        if args.tr == True:
            tr(target)
        print


if __name__ == '__main__':
    main()