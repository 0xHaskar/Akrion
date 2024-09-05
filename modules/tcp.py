#!/usr/bin/python3
import logging
import requests
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from os import system
from sys import argv


MAX_PORTS_ALLOWED = 2
clients = {}

alerts = []

DISCORD_WEBHOOK_URL = "WEBHOOK_URL"

def send_discord_alert(src_ip):
    embed = {
        "embeds": [
            {
                "title": "🛡️ Port Scanning Detected!",
                "description": f"Port scanning detected from IP: **{src_ip}**",
                "color": 16711680,  # Red color
                "fields": [
                    {
                        "name": "Source IP",
                        "value": src_ip,
                        "inline": True
                    },
                    {
                        "name": "Alert Level",
                        "value": "High",
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "Akrion Alert",
                },
                "timestamp": datetime.utcnow().isoformat()  # Add timestamp
            }
        ]
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=embed)
        if response.status_code == 204:
            print(f"Alert sent to Discord for {src_ip}")
        else:
            print(f"Failed to send alert to Discord: {response.status_code}")
    except Exception as e:
        print(f"Error sending alert to Discord: {e}")


def alert(src_ip):
	if src_ip in alerts:
		return
	print("[!] port scanning %s" % src_ip)
	send_discord_alert(src_ip)
	alerts.append(src_ip)
	

def parse(p):
	if IP in p and TCP in p:
		src_ip = p[IP].src
		src_port = p[TCP].sport
		dst_port = p[TCP].dport
		print("[+] %s:%d -> %s:%d" % (src_ip, src_port, ip, dst_port))
		if not src_ip in clients:
			clients[src_ip] = set()
		clients[src_ip].add(dst_port)
		if len(clients[src_ip]) > MAX_PORTS_ALLOWED:
			alert(src_ip)

conf.iface = argv[1]
ip = conf.iface.ip
sniff(iface=conf.iface, prn=parse, filter='tcp[tcpflags] == tcp-syn and dst host %s'%ip)
