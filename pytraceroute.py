#!/usr/bin/env python3
# pytraceroute.py
# input : IP address to do traceroute to
# output: "public_addr"  if traceroute made it to a public address
#         "ttl_expired"  if traceroute TTL expired
#         "dest_reached" if traceroute reached destination ip
#         "host_unreachable" if traceroute cannot reach host

import socket
import random
import struct
import time
import sys

__all__ = ['Tracer']

def debug(message):
    debug_flag = False
    if debug_flag == True:
        print(message)

def isPublicAddress(addr):
    # addr : ipv4 address
    octets = addr.split('.')
    isPublicAddress = True
    if octets[0] == "10": 
        isPublicAddress = False 
    if octets[0] == "172" and 16<=int(octets[1])<=31 :
        isPublicAddress = False
    elif octets[0] == "192" and octets[1] == "168":
        isPublicAddress = False
    return isPublicAddress

class Tracer(object):
    def __init__(self, dst, hops=30):
        """
        Initializes a new tracer object

        Args:
            dst  (str): Destination host to probe
            hops (int): Max number of hops to probe

        """
        self.dst = dst
        self.hops = hops
        self.ttl = 1

        # Pick up a random port in the range 33434-33534
        self.port = random.choice(range(33434, 33535))

    def run(self):
        """
        Run the tracer

        Raises:
            IOError

        Returns:
            "public_addr" or "ttl_expired" or "dest_reached" or "host_unreachable"
        """
        try:
            dst_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}'.format(self.dst, e))

        text = 'traceroute to {} ({}), {} hops max'.format(
            self.dst,
            dst_ip,
            self.hops
        )

        debug(text)

        # holds the previous ip address to detect whether it's an unreachable host
        prev = None    

        while True:
            startTimer = time.time()
            receiver = self.create_receiver()
            sender = self.create_sender()
            sender.sendto(b'', (self.dst, self.port))

            addr = None
            try:
                data, addr = receiver.recvfrom(1024)
                entTimer = time.time()
            except socket.error:
                pass
                # raise IOError('Socket error: {}'.format(e))
            finally:
                receiver.close()
                sender.close()

            if addr:
                timeCost = round((entTimer - startTimer) * 1000, 2)
                debug('{:<4} {} {} ms'.format(self.ttl, addr[0], timeCost))
                # change the following if statement
                #if addr[0] == dst_ip:
                #    break
                if isPublicAddress(addr[0]):
                    return "public_addr"
                elif addr[0] == dst_ip:
                    return "dest_reached"
                elif addr[0] == prev:
                    return "host_unreachable"
            else:
                debug('{:<4} *'.format(self.ttl))

            self.ttl += 1

            if self.ttl > self.hops:
                return "ttl_expired"

            prev = addr[0]

    def create_receiver(self):
        """
        Creates a receiver socket

        Returns:
            A socket instance

        Raises:
            IOError

        """
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        timeout = struct.pack("ll", 5, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        try:
            s.bind(('', self.port))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))

        return s

    def create_sender(self):
        """
        Creates a sender socket

        Returns:
            A socket instance

        """
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP
        )

        s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        return s

if len(sys.argv) < 2:
	print("Usage: ./pytraceroute.py <IP_ADDRESS>")
	sys.exit()
ip_address = sys.argv[1]
t = Tracer(ip_address)
result = t.run()
print(result)
