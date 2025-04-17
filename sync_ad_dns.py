#!/usr/bin/env python3

import os
import sys
import logging
import pynetbox
import dns.zone
import dns.resolver
import dns.query
import dns.reversename
from dns.exception import DNSException
from requests.exceptions import RequestException
import requests

# --- Standard Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

# --- Configuration ---
NETBOX_URL = os.getenv('NETBOX_URL', '')
NETBOX_TOKEN = os.getenv('NETBOX_TOKEN', '')
AD_DNS_SERVERS = os.getenv('AD_DNS_SERVERS', '').split(',')
NETBOX_DNS_VIEW_NAME = os.getenv('NETBOX_DNS_VIEW_NAME', 'Internal')
DEFAULT_TTL = 3600

DEFAULT_SOA_MNAME = ""
DEFAULT_SOA_RNAME = ""

ZONES_TO_SYNC = [
    {'zone_name': '', 'is_reverse': False},
    ]

SUPPORTED_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'PTR', 'MX', 'SRV']
DNS_API_BASE_PATH = "api/plugins/netbox-dns/"


def get_netbox_api():
    try:
        nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
        nb.http_session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        log.info(f"Connected to NetBox API: {NETBOX_URL}")
        return nb
    except Exception as e:
        log.error(f"Failed to connect to NetBox API: {e}")
        sys.exit(1)


def get_or_create_nb_object(nb_session, object_api_path, filter_data, create_data, object_type="object"):
    relative_api_url = f"{DNS_API_BASE_PATH}{object_api_path}"
    full_api_url = f"{NETBOX_URL.rstrip('/')}/{relative_api_url.lstrip('/')}"
    try:
        nb_session.headers.update({'Authorization': f'Token {NETBOX_TOKEN}'})
        response = nb_session.get(full_api_url, params=filter_data)
        response.raise_for_status()
        result = response.json()
        if result and result.get('count', 0) > 0:
            return result['results'][0]
        create_response = nb_session.post(full_api_url, json=create_data)
        create_response.raise_for_status()
        return create_response.json()
    except RequestException as e:
        log.error(f"NetBox API error accessing {object_api_path} for {object_type}: {e}")
        if e.response is not None:
            log.error(f"API response status: {e.response.status_code}")
            log.error(f"API response detail: {e.response.text}")
        return None


def get_ad_zone_data(zone_name, dns_servers):
    for server_ip in dns_servers:
        try:
            return dns.query.xfr(server_ip, zone_name, timeout=15.0)
        except Exception:
            continue
    return None


def sync_dns_record(nb_session, nb_zone_id, zone_name_str, nb_view_id, record_name, record_type, record_value, record_ttl=None, record_priority=None):
    """Creates or updates a DNS record in NetBox using direct HTTP session calls."""
    records_url = f"{NETBOX_URL.rstrip('/')}/{DNS_API_BASE_PATH}records/"

    record_name_str = record_name.to_text(omit_final_dot=True)
    if record_name_str == zone_name_str:
        record_name_str = '@'

    srv_priority = srv_weight = srv_port = None
    processed_value = None
    target_fqdn = None
    if "_" in record_name_str and record_type in ("A", "AAAA", "CNAME"):
        log.warning(f"Skipping {record_type} record with invalid hostname: {record_name_str}")
        return None
    try:
        if record_type == 'TXT':
            if hasattr(record_value, 'strings'):
                processed_value = ''.join(s.decode() for s in record_value.strings)
            else:
                processed_value = str(record_value).strip('"')
        elif record_type == 'CNAME' and isinstance(record_value, dns.name.Name):
            processed_value = record_value.to_text(omit_final_dot=False)
            if '\\' in processed_value or ',' in processed_value:
                log.warning(f"Skipping malformed CNAME value: {processed_value}")
                return None
        elif record_type == 'SRV':
            srv_priority = int(record_value.priority)
            srv_weight = int(record_value.weight)
            srv_port = int(record_value.port)
            target_fqdn = record_value.target.to_text()
            if not target_fqdn.endswith('.'):
                target_fqdn += '.'
            processed_value = f"{srv_priority} {srv_weight} {srv_port} {target_fqdn}"

        elif record_type == 'MX':
            record_priority = int(record_value.preference)
            target_fqdn = record_value.exchange.to_text()
            if not target_fqdn.endswith('.'):
                target_fqdn += '.'
            processed_value = f"{record_priority} {target_fqdn}"

        elif isinstance(record_value, dns.name.Name):
            processed_value = record_value.to_text(omit_final_dot=True)
        else:
            processed_value = str(record_value)
    except Exception as e:
        log.warning(f"Failed to parse {record_type} record for {record_name_str}: {e}")
        return None

    api_data = {
        "zone": nb_zone_id,
        "name": record_name_str,
        "type": record_type,
        "value": processed_value,
        "ttl": record_ttl or DEFAULT_TTL,
        **({"view": nb_view_id} if nb_view_id is not None else {}),
        **({
            "priority": record_priority,
            "target": target_fqdn
        } if record_type == "MX" else {}),
        **({
            "priority": srv_priority,
            "weight": srv_weight,
            "port": srv_port,
            "target": target_fqdn
        } if record_type == "SRV" else {})
    }

    filter_params = {
        "zone_id": nb_zone_id,
        "name": record_name_str,
        "type": record_type,
        **({"view_id": nb_view_id} if nb_view_id is not None else {"view_id": "null"}),
    }

    try:
        nb_session.headers.update({'Authorization': f'Token {NETBOX_TOKEN}'})
        response = nb_session.get(records_url, params=filter_params)
        response.raise_for_status()
        existing = response.json()
        if existing.get('count', 0) > 0:
            return existing['results'][0]
        create_response = nb_session.post(records_url, json=api_data)
        create_response.raise_for_status()
        return create_response.json()
    except Exception as e:
        log.error(f"Failed to create/update {record_type} record {record_name_str}: {e}")
        if hasattr(e, "response") and e.response is not None:
            log.error(f"Response Status Code: {e.response.status_code}")
            log.error(f"Response Body: {e.response.text}")
        return None

if __name__ == "__main__":
    nb = get_netbox_api()
    nb_session = nb.http_session
    nb_view_id = None
    records_processed = zones_synced = zones_failed = 0

    mname_ns = get_or_create_nb_object(nb_session, "nameservers/", {"name": DEFAULT_SOA_MNAME.rstrip('.')}, {"name": DEFAULT_SOA_MNAME.rstrip('.')})
    if not mname_ns:
        sys.exit(1)

    if NETBOX_DNS_VIEW_NAME:
        view_slug = NETBOX_DNS_VIEW_NAME.lower().replace(' ', '-')
        view_obj = get_or_create_nb_object(nb_session, "views/", {"slug": view_slug}, {"name": NETBOX_DNS_VIEW_NAME, "slug": view_slug})
        if not view_obj:
            sys.exit(1)
        nb_view_id = view_obj['id']

    for zone in ZONES_TO_SYNC:
        zone_name = zone['zone_name']
        zone_obj = get_or_create_nb_object(nb_session, "zones/", {"name": zone_name}, {
            "name": zone_name,
            "status": "active",
            "default_ttl": DEFAULT_TTL,
            "soa_mname": mname_ns['id'],
            "soa_rname": DEFAULT_SOA_RNAME,
            **({"view": nb_view_id} if nb_view_id else {})
        })
        if not zone_obj:
            zones_failed += 1
            continue

        zone_data = get_ad_zone_data(zone_name, AD_DNS_SERVERS)
        if not zone_data:
            zones_failed += 1
            continue

        try:
            for message in zone_data:
                for rrset in message.answer:
                    rtype = dns.rdatatype.to_text(rrset.rdtype)
                    if rtype in SUPPORTED_RECORD_TYPES:
                        for rdata in rrset:
                            result = sync_dns_record(nb_session, zone_obj['id'], zone_name, nb_view_id, rrset.name, rtype, rdata, rrset.ttl)
                            if result:
                                records_processed += 1
            zones_synced += 1
        except Exception as e:
            log.error(f"Error processing records for {zone_name}: {e}")
            zones_failed += 1

    log.info("--- Sync Summary ---")
    log.info(f"Zones Synced: {zones_synced}")
    log.info(f"Zones Failed: {zones_failed}")
    log.info(f"Records Processed: {records_processed}")
