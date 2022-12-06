# VirusTotal Enrich Connector

## Installation

1. Setting environment variable in docker-compose.yml

    | Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
    | ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
    | `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
    | `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
    | `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
    | `virustota_token`                    | `VIRUSTOTAL_TOKEN`                  | Yes          | Virustotal api token.                                                                                                                                      |

2. Build image

   ```bash
   docker build . -t virustotal-enrich-connector:5.4.1
   ```

3. Add connector settings to platform docker-compose.yml

    ```yaml
    # OpenCTI-Platform docker-compose.yml
    ...
    virustotal-enrich-connector:
        image: virustotal-enrich-connector:5.4.1
        environment:
        - OPENCTI_URL=http://opencti:8080
        - OPENCTI_TOKEN=CHANGEME
        - CONNECTOR_ID=CHANGEME
        - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
        - CONNECTOR_NAME=virustotal_enrichment_connector
        - CONNECTOR_SCOPE=StixFile
        - CONNECTOR_AUTO=True
        - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
        - CONNECTOR_LOG_LEVEL=info
        - VIRUSTOTAL_TOKEN=CHANGEME
        restart: always
    ```


4. Start OpenCTI

    ```bash
    docker compose up -d
    ```

### Requirements

- OpenCTI Platform >= 5.4.1
