import json
import socket
import dnslib as dns
from src.resolver import Resolver


class DNSServer:
    def __init__(self, server_file: str, resolver: Resolver):
        self.resolver = resolver

        # load records
        with open(server_file, "r") as f:
            data: dict = json.load(f)

        self.state: dict = data["state"]
        self.host: str = data["server"]["host"]
        self.port: int = data["server"]["port"]
        print(
            f"{self.host}:{self.port} loaded from {server_file}:\n\trecords={len(self.state['records'])}\n\tzones={len(self.state['zones'])}"
        )

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"DNS Server running on {self.host}:{self.port}")

        while True:
            data, addr = sock.recvfrom(512)  # DNS UDP max 512 bytes
            print(f"{':'.join(map(str, addr))} sends {len(data)} bytes")
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
