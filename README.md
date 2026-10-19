# CTI Collector

![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

CTI Collector is a configurable security-event collection and enrichment script. It connects to customer SIEMs, runs the event queries configured for each customer, normalizes and aggregates matching records, and stores them in MongoDB. Queries are not limited to intrusion-prevention (IPS) events: configure one or more event types that report public-source-IP threats, such as IPS/IDS, web application firewall (WAF), firewall threat events, denial-of-service (DoS/DDoS), malware, brute-force attempts, or scanning activity.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Run Manually](#run-manually)
  - [Schedule with Cron](#schedule-with-cron)
- [Data and Enrichment](#data-and-enrichment)

## Features

- Collects events from multiple customer SIEM instances in one run.
- Currently supports **CryptoSIM, FortiSIEM, Graylog, Logsign, and IBM QRadar**, with additional SIEM integrations planned for future releases.
- Supports configurable event queries per customer and threat category, such as IPS/IDS, WAF, firewall threats, DoS/DDoS, malware, brute-force attempts, and scanning activity.
- Validates and aggregates public-source-IP event data, excluding private IPs and configured IP addresses or CIDR ranges.
- Stores normalized event records and CVE details in MongoDB.
- Enriches source IPs with a score, severity, country, and location.
- Looks up CVE details from Shodan's CVE database when a CVE identifier is found in an attack name.

## Requirements

- Python **3.12 or newer**
- MongoDB (local or remote)
- Network access to the configured SIEM APIs
- An IPinfo token for authenticated geolocation requests (optional)

## Installation

Clone the repository and create a virtual environment using a Python 3.12+ interpreter:

```bash
git clone https://github.com/musaokankurtkaya/cti-collector
cd cti-collector
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Configuration

Copy the example configuration to create your local configuration:

```bash
cp src/config/config.example.ini src/config/config.ini
```

Edit `src/config/config.ini` before running the collector. This local file is excluded from version control.

### General settings

| Setting | Description |
| --- | --- |
| `[app] env` | Runtime mode: `dev` or `prod`. |
| `[app] query_interval` | Look-back interval, in minutes, sent to each SIEM query. Default: `15`. |
| `[app] query_limit` | Maximum number of events requested per query. Default: `9999`. |
| `[mongodb] uri` | Optional full MongoDB connection URI. When set, it takes precedence over host and port. |
| `[mongodb] host`, `port` | MongoDB host and port when `uri` is not set. |
| `[mongodb] username`, `password` | MongoDB credentials; set both when authentication is enabled. |
| `[mongodb] database` | Database name. The example uses `cti`. |
| `[ipinfo] url`, `token` | IPinfo API URL and optional token. Without a token, requests are sent unauthenticated and may be subject to service limits. |

### Customer settings and event queries

Each customer needs its own section named `[customerN]`, where `N` is a number that is **different from every other customer section number**. For example, if the configuration already has `[customer1]` and `[customer2]`, add a new customer as `[customer3]`. The number identifies the section; it does not need to match a customer ID in another system.

Each customer section must define the customer's details and SIEM connection:

| Key | Description |
| --- | --- |
| `c_name` | Customer name stored with collected events. |
| `c_sector` | Customer sector stored with collected events. |
| `c_fw_type` | Firewall type or related customer metadata. |
| `c_siem_name` | SIEM adapter: `cryptosim`, `fortisiem`, `graylog`, `logsign`, or `qradar`. |
| `c_siem_url` | Base URL of the SIEM service. |
| `c_siem_username`, `c_siem_password` | SIEM credentials. |

Add a `c_siem_<event_type>_query` setting for each kind of event you want that customer to collect. The event type is a user-defined label taken from the query setting's name; it is not restricted to a fixed list. For example, use `ips` for intrusion-prevention events, `waf` for web application firewall events, `dos` for denial-of-service events, or `malware` for malware detections, provided your SIEM has those events and the adapter can parse them. You can configure one, several, or other query labels suited to the data in your SIEM. For example:

```ini
[customer1]
c_name = Example Customer
c_sector = Finance
c_fw_type = fortigate
c_siem_name = graylog
c_siem_url = https://siem.example.com
c_siem_username = <username>
c_siem_password = <password>
c_siem_ips_query = <your SIEM query for IPS events>
c_siem_waf_query = <your SIEM query for WAF events>
c_siem_dos_query = <your SIEM query for DoS events>
c_siem_malware_query = <your SIEM query for malware events>
```

Common event types to consider include:

| Event type label example | Security events to query |
| --- | --- |
| `ips` / `ids` | Intrusion prevention or detection alerts |
| `waf` | Web application attacks or WAF detections |
| `firewall` | Firewall threat, deny, or suspicious connection events |
| `dos` / `ddos` | Denial-of-service or distributed denial-of-service activity |
| `malware` | Malware-related detections |
| `bruteforce` | Repeated or suspicious authentication attempts |
| `scan` | Port scanning or reconnaissance activity |

These are examples, not a built-in list of event types or guarantees that every SIEM has those event categories. Choose any event-type label that is meaningful to you; the required setting format is `c_siem_<your_event_type>_query`. The `c_siem_` prefix and `_query` suffix are required, while the label between them is user-defined and may contain underscores. For example, either `c_siem_bruteforce_query` or `c_siem_brute_force_query` is valid. Use query syntax supported by the selected SIEM. Query results must expose fields the selected adapter can map to source IP, attack name, destination port, and event time. Available events and fields vary by SIEM and adapter. This collector is intended for threat events with public source IPs: private source IPs are excluded during processing.

Some adapters also accept a `c_siem_<event_type>_query_attrs` setting for additional query attributes. For example, the FortiSIEM adapter uses `c_siem_ips_query_attrs` when configured. Check the adapter behavior before adding adapter-specific attributes.

### IP exclusions and attack tags

- `src/data/siems/excluded_ips.json` contains IP addresses or CIDR ranges to exclude. Private IPs are excluded automatically as well.
- `src/data/siems/attack_tags.json` maps attack-name text to categories. CVE identifiers found in attack names are categorized as CVEs and can be enriched from Shodan's CVE database.

## Usage

### Run Manually

With the virtual environment active and configuration complete, run the collector from the repository root:

```bash
python3 -m src
```

Each execution queries all configured customer sections and all their configured event queries. The application performs one collection run and does not schedule itself.

### Schedule with Cron

For continuous automation on Linux or macOS, schedule the script with cron. The default `query_interval` is 15 minutes, so the example below runs the collector every 15 minutes.

1. Open your crontab:

   ```bash
   crontab -e
   ```

2. Add a job using the absolute path to the project and its virtual-environment Python interpreter:

   ```cron
   */15 * * * * cd /absolute/path/to/cti-collector && /absolute/path/to/cti-collector/.venv/bin/python -m src
   ```

Replace `/absolute/path/to/cti-collector` with the directory where you cloned the project. If you change `[app] query_interval`, update the cron schedule to use the same interval. For example, `query_interval = 15` pairs with `*/15 * * * *`.

Use cron's `*/N` minute syntax when the interval divides evenly into an hour (such as 5, 10, 15, or 30 minutes). For other schedules or on Windows, use a scheduler configured to run the command from the repository root at the desired interval. Ensure scheduled runs do not overlap; each run queries the configured look-back window and may process events returned by earlier runs again.

## Data and Enrichment

The collector uses the configured MongoDB database and creates:

- **`events`** — normalized event records keyed by event type, source IP, and customer. Records include attack names and categories, destination ports, occurrence counts, first/last-seen times, score/severity, and country/location when available.
- **`cves`** — CVE details retrieved from `cvedb.shodan.io` for CVEs found in collected events.

IP severity bands are **Low** (0–25), **Medium** (26–50), **High** (51–75), and **Critical** (76–100). Scores are calculated using event recency, occurrence counts, and attack counts.

The collector sends outbound requests to configured SIEMs, IPinfo (for geolocation), and Shodan's CVE database (for CVE enrichment). Configure MongoDB access controls, network restrictions, and data retention appropriately for your environment.
