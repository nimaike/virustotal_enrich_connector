import requests
from typing import Any
from dataclasses import dataclass
from dacite import from_dict
from urllib.parse import urljoin


@dataclass
class FileBehaviourDnsLookups:
    resolved_ips: list[str]
    hostname: str


@dataclass
class FileBehaviourAttribute:
    dns_lookups: list[FileBehaviourDnsLookups]


@dataclass
class FileBehaviourData:
    attributes: dict[str, Any]


@dataclass
class FileBehaviour:
    data: list[FileBehaviourData]


@dataclass
class VirusTotalClient:
    token: str
    baes_url: str = "https://www.virustotal.com"

    def __post_init__(self):
        self.header: dict[str, str] = {"x-apikey": self.token}

    def _get_file_behavior(self, sha256: str) -> FileBehaviour:
        endpoint: str = urljoin(self.baes_url, f"/api/v3/files/{sha256}/behaviours")
        file_behaviour_json = requests.get(url=endpoint, headers=self.header).json()
        return from_dict(data_class=FileBehaviour, data=file_behaviour_json)

    def _get_dns_lookups(
        self, file_behavior: FileBehaviour
    ) -> list[FileBehaviourDnsLookups]:
        dns_lookups: list[dict[str, str | list[str]]] = []
        for data in file_behavior.data:
            if (_dns_lookups := data.attributes.get("dns_lookups")) is None:
                continue
            for _dns_lookup in _dns_lookups:
                if _dns_lookup.get("resolved_ips") and _dns_lookup.get("hostname"):
                    dns_lookups.append(_dns_lookup)

        return [
            from_dict(data_class=FileBehaviourDnsLookups, data=dns_lookup)
            for dns_lookup in dns_lookups
        ]

    def get_related_ipaddress(self, sha256: str) -> list[str] | None:
        file_behaviour = self._get_file_behavior(sha256)
        dns_lookups = self._get_dns_lookups(file_behaviour)

        related_ip_addresses = []
        for dns_lookup in dns_lookups:
            related_ip_addresses.extend(dns_lookup.resolved_ips)
        return related_ip_addresses