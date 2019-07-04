#!/usr/bin/env python
"""
File: cipscan.py
Desc: Common Industrial Protocol Scanner UDP
Version: 1.0
"""

import socket
import struct
import optparse
from IPy import IP
import sys
from multiprocessing import Process,Queue
class CipScan(Process):

    def __init__(self,iprange,options):
        Process.__init__(self)
        self.iprange=iprange
        self.options=options
    def run(self):
        for ip in self.iprange:
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                #s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) # For TCP based queries
                s.settimeout(float(self.options.timeout)/float(100))
                msg = str(ip)+":"+str(self.options.port)
                print("Scanning"+" "+msg+"\n")
                conn=s.connect((str(ip),self.options.port))
                packet=struct.pack('24B',0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                #packet=struct.pack('73B',0x70, 0x00, 0x31, 0x00, 0xc9, 0x74, 0xb8, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0x0d, 0x00, 0xfe, 0x80, 0xb1, 0x00, 0x1d, 0x00, 0xf9, 0x39, 0xcb, 0x00, 0x00, 0x00, 0x07, 0x4d, 0x00, 0x04, 0x02, 0x5c, 0x0b, 0x4f, 0x00, 0xce, 0xf0, 0x00, 0x07, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff) #PCCC communication TCP based
            except socket.error:
                msg="Failed to Connect\n"
                print(msg+"\n")
                s.close()
                break			
            try:			
                s.send(packet)
                print('Sent'+' '+packet)
            except socket.error:
                msg="Failed to Send\n"
                print(msg)
                s.close()
                break
            try:			
                recv=s.recvfrom(1024)
                print(recv)
            except socket.error:
                msg="Failed to Receive\n"
                print(msg+"\n")
                s.close()
                break
#            except socket.error:
#            	msg="Failed to Receive\n"
#                print(msg+"\n")
#                s.close()
#                break
            s.close()
        print("Scan has completed"+"\n")
        
        

def main():
    p = optparse.OptionParser(	description=' Finds CIP devices in IP range and determines Vendor Specific Information along with Internal private IP.\nOutputs in ip:port <tab> sid format.',
								prog='CipScan',
								version='CIP Scan 1.0',
								usage = "usage: %prog [options] IPRange")
    p.add_option('--port', '-p', type='int', dest="port", default=44818, help='CIP port DEFAULT:44818')
    p.add_option('--timeout', '-t', type='int', dest="timeout", default=500, help='socket timeout (mills) DEFAULT:500')
    options, arguments = p.parse_args()
    if len(arguments) == 1:
        print("Starting Common Industrial Protocol Scan"+"\n")
        i=""
        i=arguments[0]
        iprange=IP(i)
        q = Queue()
        for ip in iprange:
            print("Starting Multithreading"+"\n")
            p = CipScan(ip,options).start()
            q.put(p,False)
    else:
        p.print_help()
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Scan canceled by user.")
        print("Thank you for using CIP Scan")
#    except :
sys.exit()
