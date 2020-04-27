#!usr/bin/env python
import scapy.all as scapy
import argparse
from mac_vendor_lookup import MacLookup

def scan(ip):
    request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_request=broadcast/request
    ans_ls , unans_ls = scapy.srp(broadcast_request , timeout=1, verbose=False)
    ip_mac_list=[]
    for answer in ans_ls:
        ip_mac_dict={"ip":answer[1].psrc,"mac":answer[1].hwsrc, "vendor":MacLookup().lookup(str(answer[1].hwsrc))}
        ip_mac_list.append(ip_mac_dict)
    return ip_mac_list

def result(ip_mac_result):
    print("IP\t\t\t\tMAC ADDRESS\t\t\t\tVENDOR\n-----------------------------------------------------------------------------------------------------")
    for imresult in ip_mac_result:
        print(imresult["ip"]+"\t\t\t"+imresult["mac"] +"\t\t\t"+imresult["vendor"])

def options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target" , dest="iprange" , help="Enter IP range to find the target")
    options = parser.parse_args()
    if not options.iprange:
        parser.error("[-]please enter the ip range or ip address")
    return options



option=options()
scan_result=scan(option.iprange)
result(scan_result)