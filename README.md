Simple Python script to sync your AD DNS to Netbox-DNS plugin. Turn on AXFR to the netbox script host IP.<br/><br/>

It could probably use refinement, Python is newer to me. It works pretty well as a cron. <br/><br/>

Set these Variables:<br/>
NETBOX_URL = os.getenv('NETBOX_URL', 'https://example.com')<br/>
NETBOX_TOKEN = os.getenv('NETBOX_TOKEN', 'yeahthisisthatspicykey')<br/>
AD_DNS_SERVERS = os.getenv('AD_DNS_SERVERS', '1.2.3.4').split(',')<br/>
DEFAULT_TTL = 3600<br/><br/>

DEFAULT_SOA_MNAME = "soa.example.com"<br/>
DEFAULT_SOA_RNAME = "hostmaster.example.com"<br/><br/>

ZONES_TO_SYNC = [<br/>
    {'zone_name': 'example.com', 'is_reverse': False},<br/>
    {'3.2.1.in-addr.arpa', 'is_reverse': True},<br/>
    ]<br/><br/>
