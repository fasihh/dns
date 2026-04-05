import socket
import time
import copy
from abc import ABC, abstractmethod
from dnslib import DNSRecord, DNSHeader, RR, NS, QTYPE, A, AAAA, CNAME, MX, TXT, PTR, RCODE
from src.cache import Cache

RDATA_MAPPER = {
    "A": A,
    "AAAA": AAAA,
    "NS": NS,
    "CNAME": CNAME,
    "MX": MX,
    "TXT": TXT,
    "PTR": PTR,
}


def create_rdata(record_type: str, value):
    mapper = RDATA_MAPPER.get(record_type.upper())
    if mapper is None:
        return None
    return mapper(value)


def qtype_code(record_type: str):
    return getattr(QTYPE, record_type.upper(), None)


class Resolver(ABC):
    def __init__(self, cache: Cache, cache_ttl=60):
        self.cache = cache
        self.cache_ttl = cache_ttl

    @abstractmethod
    def resolve(self, request: DNSRecord, server_data: dict) -> bytes:
        raise NotImplementedError


class RecursiveResolver(Resolver):
    def resolve(self, request: DNSRecord, server_data: dict) -> bytes:
        """
        server_data: {
            "zones": {...},
            "records": {...}
        }
        """
        question = request.questions[0]
        qname = str(question.qname).rstrip(".")
        qtype = QTYPE[question.qtype]

        zones = server_data.get("zones", {})
        records = server_data.get("records", {})

        reply = DNSRecord(
            DNSHeader(
                id=request.header.id,
                qr=1,
                aa=1,
                ra=1, # recursion available
                rd=request.header.rd
            ),
            q=request.questions[0]
        )

        cache_key = (qname, qtype)

        # check cache
        if cache_key in self.cache:
            cached_record, expiry = self.cache[cache_key]
            record: DNSRecord = copy.deepcopy(cached_record)
            record.header.id = request.header.id

            if time.time() < expiry:
                print(f"[Cache hit] {qname} ({qtype})")
                return record.pack()
            else:
                del self.cache[cache_key]

        # check local
        answers = []
        for rec in records.get(qname, []):
            rec_type = str(rec.get("type", "")).upper()
            if rec_type == qtype:
                rdata = create_rdata(qtype, rec.get("value"))
                rtype_code = qtype_code(qtype)
                if rdata is None or rtype_code is None:
                    continue
                answers.append(RR(
                    rname=qname,
                    rtype=rtype_code,
                    rclass=1,
                    ttl=rec.get("ttl", self.cache_ttl),
                    rdata=rdata
                ))

        if answers:
            for answer in answers:
                reply.add_answer(answer)
            resp_bytes = reply.pack()
            self.cache[cache_key] = (copy.deepcopy(reply), time.time() + self.cache_ttl)
            print(f"[Resolved locally] {qname} ({qtype})")
            return resp_bytes

        # find auth server
        auth_server = self.find_authoritative(qname, zones)
        if auth_server:
            print(f"[Forwarding] {qname} -> {auth_server}")
            data = self.query_authoritative(auth_server, request)
            if data:
                self.cache[cache_key] = (DNSRecord.parse(data), time.time() + self.cache_ttl)
                return data

        # does not exist, send nxdomain
        reply.header.rcode =RCODE.NXDOMAIN
        return reply.pack()

    def find_authoritative(self, qname: str, zones: dict):
        candidate = None
        for zone in zones:
            zone = zone.rstrip(".")
            if qname.endswith(zone):
                if candidate is None or len(zone) > len(candidate):
                    candidate = zone
        if candidate:
            return zones[candidate]["ns"]
        return None

    def query_authoritative(self, server: str, request: DNSRecord) -> bytes:
        host, port = server.split(":")
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(request.pack(), (host, port))
        try:
            data, _ = sock.recvfrom(512)
        except socket.timeout:
            print(f"[Timeout] {server}")
            data = None
        finally:
            sock.close()
        return data


class IterativeResolver(Resolver):
    def resolve(self, request: DNSRecord, server_data: dict) -> bytes:
        question = request.questions[0]
        qname = str(question.qname).rstrip(".")
        qtype = QTYPE[question.qtype]

        zones = server_data.get("zones", {})
        records = server_data.get("records", {})

        reply = DNSRecord(
            DNSHeader(
                id=request.header.id,
                qr=1,
                aa=1,
                ra=0
            ),
            q=question
        )

        cache_key = (qname, qtype)

        # check cache
        if cache_key in self.cache:
            cached_record, expiry = self.cache[cache_key]
            record = copy.deepcopy(cached_record)
            record.header.id = request.header.id

            if time.time() < expiry:
                print(f"[Cache hit] {qname} ({qtype})")
                return record.pack()
            else:
                del self.cache[cache_key]

        # check local records
        answers = []
        for rec in records.get(qname, []):
            rec_type = str(rec.get("type", "")).upper()
            if rec_type == qtype:
                rdata = create_rdata(qtype, rec.get("value"))
                rtype_code = qtype_code(qtype)
                if rdata is None or rtype_code is None:
                    continue
                answers.append(RR(
                    rname=qname,
                    rtype=rtype_code,
                    rclass=1,
                    ttl=rec.get("ttl", self.cache_ttl),
                    rdata=rdata
                ))

        if answers:
            for answer in answers:
                reply.add_answer(answer)

            self.cache[cache_key] = (copy.deepcopy(reply), time.time() + self.cache_ttl)

            print(f"[Resolved locally] {qname} ({qtype})")
            return reply.pack()

        # find authoritative referral
        auth_server = self.find_authoritative(qname, zones)
        if auth_server:
            zone = self.find_zone(qname, zones)
            # return referral
            host, _ = auth_server.split(":")
            ns_name = f"ns.{zone}"

            # authority section
            reply.add_auth(RR(
                rname=zone,
                rtype=QTYPE.NS,
                rclass=1,
                ttl=self.cache_ttl,
                rdata=NS(ns_name)
            ))
            # additional section (glue)
            reply.add_ar(RR(
                rname=ns_name,
                rtype=QTYPE.A,
                rclass=1,
                ttl=self.cache_ttl,
                rdata=A(host)
            ))
            
            print(f"[Referral] {qname} -> {auth_server}")
            return reply.pack()

        # does not exist, send nxdomain
        reply.header.rcode = RCODE.NXDOMAIN
        return reply.pack()

    def find_authoritative(self, qname: str, zones: dict):
        candidate = None
        for zone in zones:
            zone = zone.rstrip(".")
            if qname.endswith(zone):
                if candidate is None or len(zone) > len(candidate):
                    candidate = zone
        if candidate:
            return zones[candidate]["ns"]
        return None

    def find_zone(self, qname: str, zones: dict):
        candidate = None
        for zone in zones:
            zone = zone.rstrip(".")
            if qname.endswith(zone):
                if candidate is None or len(zone) > len(candidate):
                    candidate = zone
        return candidate
