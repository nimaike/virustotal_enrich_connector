from stix2.v21.observables import IPv4Address, IPv6Address, DomainName
from stix2.v21.bundle import Bundle
import ipaddress
from dataclasses import dataclass

@dataclass
class VirusTotalBuilder:
    def create_ip_address_observable(self, ip_address: str) -> IPv4Address | IPv6Address | None:
        ip_address = ipaddress.ip_address(ip_address)
        if isinstance(ip_address, ipaddress.IPv4Address):  
            return IPv4Address(value=ip_address)
        elif isinstance(ip_address, ipaddress.IPv6Address):
            return IPv6Address(value=ip_address)

    def create_bundle(self, stix_objects: list[IPv4Address | IPv6Address]):
        return Bundle(objects=stix_objects)