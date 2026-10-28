# E1 lab node image: victim / gateway / attacker all run this image.
# Tools: iproute2 + arp (ARP tables), tcpdump (PCAP), curl/openssl (traffic + TLS),
# scapy (controlled ARP sending). Isolated lab use only (scope section 0).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        net-tools \
        tcpdump \
        curl \
        openssl \
        procps \
        iptables \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "scapy==2.5.0"

WORKDIR /lab
COPY gateway_server.py arp_spoof.py /lab/

# Stay alive; the runner drives each node via `docker exec`.
CMD ["sleep", "infinity"]
