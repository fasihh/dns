import json
import socket
import dnslib as dns
from src.resolver import Resolver


class DNSServer:
    def __init__(self, records_file: str, resolver: Resolver, host="0.0.0.0", port=5300):
        self.host = host
        self.port = port
        self.resolver = resolver

        # load records
        with open(records_file, "r") as f:
            self.state: dict = json.load(f)

        print(f"Loaded {len(self.state["records"])} records and {len(self.state["zones"])} zones from {records_file}")

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"DNS Server running on {self.host}:{self.port}")

        while True:
            data, addr = sock.recvfrom(512)  # DNS UDP max 512 bytes
            print(f"{":".join(map(str, addr))} sends {len(data)} bytes")
            try:
                request = dns.DNSRecord.parse(data)
            except Exception as e:
                print(f"Failed to parse DNS request: {e}")
                continue

            try:
                response_bytes = self.resolver.resolve(request, self.state)
            except Exception as e:
                print(f"Resolver failed: {e}")
                continue

            sock.sendto(response_bytes, addr)
