Simple Python script to sync your AD DNS to Netbox-DNS plugin. Turn on AXFR to the netbox script host IP.

It could probably use refinement, Python is newer to me. It works pretty well as a cron. 

Set these Variables:
NETBOX_URL = os.getenv('NETBOX_URL', 'https://example.com')
NETBOX_TOKEN = os.getenv('NETBOX_TOKEN', 'yeahthisisthatspicykey')
AD_DNS_SERVERS = os.getenv('AD_DNS_SERVERS', '1.2.3.4').split(',')
DEFAULT_TTL = 3600

DEFAULT_SOA_MNAME = "soa.example.com"
DEFAULT_SOA_RNAME = "hostmaster.example.com"

ZONES_TO_SYNC = [
    {'zone_name': 'example.com', 'is_reverse': False},
    {'3.2.1.in-addr.arpa', 'is_reverse': True},
    ]
