import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from dataclasses import dataclass
from client import VirusTotalClient
from builder import VirusTotalBuilder


@dataclass
class VirusTotalEnrichConnector:
    config_file_path: str = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"

    def __post_init__(self):
        self.config = (
            yaml.load(open(self.config_file_path), Loader=yaml.SafeLoader)
            if os.path.isfile(self.config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(self.config)
        self.token = get_config_variable(
            "VIRUSTOTAL_TOKEN", ["virustotal", "token"], self.config, False
        )

    def _process_message(self, data: dict[str, str]) -> None:
        vt_client = VirusTotalClient(token=self.token)
        vt_builder = VirusTotalBuilder()

        observable = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])
        related_ip_addresses = vt_client.get_related_ipaddress(
            sha256=observable["observable_value"]
        )

        if related_ip_addresses:
            stix2_ipaddress_observables = [
                vt_builder.create_ip_address_observable(ip_address)
                for ip_address in related_ip_addresses
            ]
            stix2_bundle = vt_builder.create_bundle(stix2_ipaddress_observables)

            self.helper.send_stix2_bundle(stix2_bundle.serialize())

    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = VirusTotalEnrichConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
