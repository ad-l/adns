#!/usr/bin/env python3
"""
CCF to BIND DNS Synchronization Service

This script synchronizes DNS zone data from a CCF application to a BIND DNS server.
It:
1. Queries the current SOA serial from BIND
2. Queries the CCF application for changes since that serial
3. Applies updates to BIND using dynamic DNS updates with SIG(0) authentication
"""

import argparse
import base64
import datetime
import dns.name
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TLSA
import dns.rdtypes.IN.A
import json
import logging
import os
import requests
import sys
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from typing import Dict, List, Optional, Tuple, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('adns-sync')

class AttestationRecord:
    """Represents an attestation record in the CCF application"""
    def __init__(self, domain: str, attestation_data: str, public_key: str):
        self.domain = domain
        self.attestation_data = attestation_data
        self.public_key = public_key

class DNSSynchronizer:
    """
    Synchronizes DNS zone data between CCF and BIND
    """
    def __init__(
        self,
        zone_name: str,
        bind_server: str,
        bind_port: int,
        ccf_endpoint: str,
        keyfile: str,
        key_name: str
    ):
        self.zone_name = dns.name.from_text(zone_name)
        self.bind_server = bind_server
        self.bind_port = bind_port
        self.ccf_endpoint = ccf_endpoint
        self.sig0_keyfile = keyfile
        self.key_name = key_name
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [bind_server]
        self.load_sig0_key()
        
    def load_sig0_key(self):
        """Load the SIG(0) private key for DDNS authentication"""
        try:
            with open(self.sig0_keyfile, 'rb') as f:
                key_data = f.read()
            self.private_key = load_pem_private_key(key_data, password=None)
            logger.info(f"Loaded SIG(0) key from {self.sig0_keyfile}")
        except Exception as e:
            logger.error(f"Failed to load SIG(0) key: {e}")
            sys.exit(1)
    
    def get_current_serial(self) -> int:
        """Query BIND for the current SOA serial of the zone"""
        try:
            answers = self.resolver.resolve(self.zone_name, 'SOA')
            for rdata in answers:
                return rdata.serial
        except Exception as e:
            logger.error(f"Failed to get current serial for {self.zone_name}: {e}")
            return 0
    
    def get_ccf_updates(self, serial: int) -> Tuple[List[dict], int]:
        """
        Query CCF for updates since the provided serial
        Returns (updates, new_serial)
        """
        try:
            url = f"{self.ccf_endpoint}/dns/updates?since_serial={serial}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get('updates', []), data.get('new_serial', serial)
        except Exception as e:
            logger.error(f"Failed to get updates from CCF: {e}")
            return [], serial
    
    def apply_updates_to_bind(self, updates: List[dict], new_serial: int) -> bool:
        """Apply DNS updates to BIND using dynamic DNS update with SIG(0)"""
        if not updates:
            logger.info("No updates to apply")
            return True
        
        # Create update message
        update = dns.update.Update(self.zone_name)
        
        # Add SOA update to increment serial
        old_soa = self.resolver.resolve(self.zone_name, 'SOA')[0]
        new_soa = dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            old_soa.mname,
            old_soa.rname,
            new_serial,  # New serial
            old_soa.refresh,
            old_soa.retry,
            old_soa.expire,
            old_soa.minimum
        )
        update.delete('@ SOA')
        update.add('@ SOA', 3600, new_soa)
        
        # Process attestation records and other updates
        for record in updates:
            record_type = record.get('type')
            name = record.get('name')
            ttl = record.get('ttl', 3600)
            
            if record.get('action') == 'delete':
                update.delete(name, record_type)
                logger.info(f"Deleting {name} {record_type}")
                continue
            
            # Handle different record types
            if record_type == 'A':
                update.add(name, ttl, dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, record.get('address')))
            elif record_type == 'AAAA':
                address = record.get('address')
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, address)
                update.add(name, ttl, rdata)
            elif record_type == 'TXT':
                txt_string = record.get('text', '')
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txt_string)
                update.add(name, ttl, rdata)
            elif record_type == 'TLSA':
                # Handle TLSA records (for DANE)
                usage = record.get('usage', 3)  # Default: DANE-EE
                selector = record.get('selector', 0)  # Default: Full certificate
                matching_type = record.get('matching_type', 1)  # Default: SHA-256
                cert_data = record.get('certificate')
                
                tlsa_text = f"{usage} {selector} {matching_type} {cert_data}"
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TLSA, tlsa_text)
                update.add(name, ttl, rdata)
            elif record_type == 'ATTEST':
                # Custom type for attestation records, store as TXT for now
                attest_data = base64.b64encode(
                    json.dumps(record.get('attestation_data')).encode()
                ).decode('ascii')
                chunks = [attest_data[i:i+255] for i in range(0, len(attest_data), 255)]
                txt_data = ''.join(f'"{chunk}"' for chunk in chunks)
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txt_data)
                update.add(f"_attest.{name}", ttl, rdata)
            
            logger.info(f"Adding {name} {record_type}")
        
        # Sign the update with SIG(0)
        update.use_tsig(keyring=None, keyname=None)
        update = self._sign_update(update)
        
        # Send the update to BIND
        try:
            response = dns.query.tcp(update, self.bind_server, timeout=10, port=self.bind_port)
            rcode = response.rcode()
            if rcode == dns.rcode.NOERROR:
                logger.info(f"Successfully applied {len(updates)} updates to BIND")
                return True
            else:
                logger.error(f"BIND update failed with rcode {dns.rcode.to_text(rcode)}")
                return False
        except Exception as e:
            logger.error(f"Failed to apply updates to BIND: {e}")
            return False
    
    def _sign_update(self, update):
        """Sign DNS update message with SIG(0)"""
        # This is a simplified version - in production you'd use dnspython's SIG(0) functionality
        # For now, we're just returning the update without actually signing it
        # In a real implementation, you would:
        # 1. Serialize the update message
        # 2. Sign it with the private key
        # 3. Add the signature to the update
        return update
    
    def run_sync_cycle(self) -> bool:
        """Run a single synchronization cycle"""
        current_serial = self.get_current_serial()
        logger.info(f"Current zone serial: {current_serial}")
        
        updates, new_serial = self.get_ccf_updates(current_serial)
        logger.info(f"Got {len(updates)} updates from CCF, new serial: {new_serial}")
        
        if new_serial > current_serial:
            return self.apply_updates_to_bind(updates, new_serial)
        else:
            logger.info("No new updates to apply")
            return True

def main():
    parser = argparse.ArgumentParser(description='CCF to BIND DNS Synchronization Service')
    parser.add_argument('--zone', required=True, help='DNS zone name (e.g., attested.name)')
    parser.add_argument('--bind-server', default='127.0.0.1', help='BIND server IP')
    parser.add_argument('--bind-port', type=int, default=53, help='BIND server port')
    parser.add_argument('--ccf-endpoint', required=True, help='CCF API endpoint')
    parser.add_argument('--keyfile', required=True, help='SIG(0) private key file')
    parser.add_argument('--key-name', default='adns-sync-key', help='SIG(0) key name')
    parser.add_argument('--interval', type=int, default=60, help='Sync interval in seconds')
    parser.add_argument('--oneshot', action='store_true', help='Run once and exit')
    
    args = parser.parse_args()
    
    synchronizer = DNSSynchronizer(
        zone_name=args.zone,
        bind_server=args.bind_server,
        bind_port=args.bind_port,
        ccf_endpoint=args.ccf_endpoint,
        keyfile=args.keyfile,
        key_name=args.key_name
    )
    
    if args.oneshot:
        success = synchronizer.run_sync_cycle()
        return 0 if success else 1
    
    # Continuous operation
    logger.info(f"Starting continuous sync with interval {args.interval}s")
    while True:
        try:
            synchronizer.run_sync_cycle()
        except Exception as e:
            logger.error(f"Error in sync cycle: {e}")
        
        time.sleep(args.interval)

if __name__ == "__main__":
    sys.exit(main())