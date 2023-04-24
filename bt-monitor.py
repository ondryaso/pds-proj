#!/usr/bin/env python3
# bt-monitor.py
# Author: Ondřej Ondryáš (xondry02@stud.fit.vut.cz)

import itertools
import sys
import struct
import socket

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, defragment, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapNgReader
from bencoder import bdecode2, BTFailure
from typing import *


class Tracker:
    def __init__(self, address):
        self.address = address


class Peer:
    def __init__(self, info_hash, peer_id, ip, port):
        self.info_hash = info_hash
        self.port = port
        self.ip = ip
        self.peer_id = peer_id
        self.from_dht_nodes = []
        self.from_trackers = []
        self.own_dht_node = None


class DHTNode:
    def __init__(self, node_id, ip, port):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.known_nodes = {}
        self.known_peers = {}

    def add_known_nodes(self, info_hash, nodes):
        if info_hash not in self.known_nodes:
            self.known_nodes[info_hash] = []

        for node in nodes:
            self.known_nodes[info_hash].append(node)

    def add_known_peer(self, info_hash, peer):
        if info_hash not in self.known_peers:
            self.known_peers[info_hash] = []

        if peer in self.known_peers[info_hash]:
            return

        print(
            f"adding peer for {info_hash.hex()}: {peer.ip}\t{peer.port}")
        self.known_peers[info_hash].append(peer)
        if self not in peer.from_dht_nodes:
            peer.from_dht_nodes.append(self)


class Monitor:

    def __init__(self):
        self.dns_possible_dht: Dict[str, str] = {}
        """IP-hostname mappings for possible DHT nodes discovered from DNS queries"""
        self.dns_possible_trackers: Dict[str, str] = {}
        """IP-hostname mappings for possible trackers discovered from DNS queries"""
        self.dht_transactions: Dict[Tuple[str, int, str, int, bytes], Tuple[DHTNode, str]] = {}
        """A temporary storage for IDs of discovered DHT requests"""

        self.peer_dicts: Dict[bytes, Dict[Tuple[str, int], Peer]] = {}
        """Mappings of an info-hash to a collection of its discovered Peers, identified by their (IP, port
           contact information."""
        self.peers_by_ips: Dict[Tuple[str, int], List[Peer]] = {}
        """Mappings of an (IP, port) tuple to a list of Peer objects with this contact information (each torrent gets
           its own Peer object)."""

        self.dht_bootstrap_nodes: List[DHTNode] = []
        """DHT nodes that haven't been discovered from another known DHT node."""
        # self.dht_nodes = []
        self.dht_nodes_by_ips: Dict[Tuple[str, int], DHTNode] = {}
        """Mappings of an (IP, port) tuple to a single DHT node object."""

        self.out = OutputManager(self)
        """The output generator."""

    # noinspection PyTypeChecker
    def trace_udp_pcapng(self, file):
        """Reads a Pcap(ng) file, defragments IP packets and runs tracing on found UDP datagrams."""
        reader = RawPcapNgReader(file)
        fragments = []

        for pkt_data in reader:
            p = Ether(pkt_data[0])

            if not isinstance(p[1], IP):
                continue

            if p[IP].flags & 1 == 1 or p[IP].frag > 0:
                # Fragmented IP packet
                fragments += p
                fragments = defragment(fragments)
                defragmented = []
                for f in fragments:
                    if f[IP].flags & 1 == 0 and f[IP].frag == 0:
                        defragmented.append(f)
                fragments = [f for f in fragments if f not in defragmented]
                for df in defragmented:
                    if isinstance(df[2], UDP):
                        self.trace_udp(df)

            elif isinstance(p[2], UDP):
                self.trace_udp(p)

    def trace_udp(self, packet):
        payload = bytes(packet[3])
        if len(payload) < 4:
            return

        # try interpreting as a DHT message
        if self.is_possible_dht(payload):
            self.trace_dht(packet, payload)
            return

        # try interpreting as a uTP / BT Peer proto message
        if self.is_possible_btp(payload):
            self.trace_btp(payload)
            return

        # may be a DNS request to a tracker
        if DNS in packet:
            self.trace_dns(packet)
            return

        # or it may be the UDP Tracker Protocol
        if self.is_udp_tracker_proto(payload):
            self.trace_udp_tracker_proto(payload)

    @staticmethod
    def is_possible_dht(payload):
        # dht packets are bencoded dicts, they must start with 'dX:' where X is a digit
        if payload[0] != 100 or payload[1] < 48 or payload[1] > 57 or payload[2] != 58:
            return False
        # ... and end with 'e'
        if payload[-1] != 101:
            return False

        return True

    def is_possible_btp(self, payload):
        return False

    def is_udp_tracker_proto(self, payload):
        return False

    def get_dht_flow(self, packet, trans_id):
        key_cand = (packet[IP].dst, packet[IP].src, packet[UDP].dport, packet[UDP].sport, trans_id)
        if key_cand in self.dht_transactions:
            return self.dht_transactions.pop(key_cand)
        key_cand = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, trans_id)
        if key_cand in self.dht_transactions:
            return self.dht_transactions.pop(key_cand)

        return None

    def set_dht_flow(self, packet, trans_id, val):
        key_cand = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, trans_id)
        if key_cand not in self.dht_transactions:
            key_cand = (packet[IP].dst, packet[IP].src, packet[UDP].dport, packet[UDP].sport, trans_id)

        self.dht_transactions[key_cand] = val

    def trace_dht(self, packet, payload):
        try:
            decoded, _ = bdecode2(payload)
        except BTFailure:
            return

        if b'y' not in decoded:
            # message type not present
            return

        msg_type = decoded[b'y']
        if msg_type == b'q':
            if b'q' not in decoded or b'a' not in decoded:
                return
            self.trace_dht_req(packet, decoded)
        elif msg_type == b'r':
            if b'r' not in decoded:
                return
            self.trace_dht_resp(packet, decoded)

    def trace_dht_req(self, packet, decoded):
        req_type = decoded[b'q']
        args = decoded[b'a']

        if b'info_hash' not in args:
            return

        i_hash = args[b'info_hash']
        node, had_contact = self.get_or_add_node(None, packet[IP].dst, packet[UDP].dport)

        if req_type == b'get_peers':
            if b't' in decoded:
                self.set_dht_flow(packet, decoded[b't'], (node, i_hash))
            if not had_contact:
                self.dht_bootstrap_nodes.append(node)
                #self.out.report_bootstrap_node(node)

        elif req_type == b'announce_peer':
            p = self.get_or_add_peer(i_hash, packet[IP].src, packet[UDP].sport)
            node.add_known_peer(i_hash, p)

    def trace_dht_resp(self, packet, decoded):
        resp = decoded[b'r']
        if b'id' not in resp:
            return

        node_id = resp[b'id']
        if b't' in decoded:
            node: DHTNode
            req = self.get_dht_flow(packet, decoded[b't'])

            if req is None:
                print("unsolicited dht response")
                return

            node, i_hash = req
            if node.node_id is not None and node.node_id != node_id:
                print(f"node id mismatch, prev: {node.node_id.hex()}, now got in response: {node_id.hex()}")

            node.node_id = node_id
            if b'values' in resp:
                self.extract_peers(i_hash, node, resp[b'values'])

            if b'nodes' in resp:
                self.extract_nodes(resp[b'nodes'])

    def get_or_add_node(self, node_id, ip, port):
        contact = (ip, port)
        node_exists = contact in self.dht_nodes_by_ips
        if node_exists:
            node = self.dht_nodes_by_ips[contact]
        else:
            node = DHTNode(node_id, ip, port)
            # self.dht_nodes.append(node)
            self.dht_nodes_by_ips[contact] = node

        # we know BT peer(s) that hosts this DHT node, link them
        if contact in self.peers_by_ips:
            for peer in self.peers_by_ips[contact]:
                if peer.own_dht_node is not None and peer.own_dht_node != node:
                    print(f"warning: overwriting associated node for peer {peer.peer_id}")
                peer.own_dht_node = node

        return node, node_exists

    def get_or_add_peer(self, info_hash, ip: str, port: int, peer_id=None):
        """Gets a Peer object for a given combination of torrent (info_hash), ip and port.
           Creates a new one if this Peer hasn't been discovered yet."""

        if info_hash not in self.peer_dicts:
            self.peer_dicts[info_hash] = {}

        contact = (ip, port)
        if contact in self.peer_dicts[info_hash]:
            # this peer is already added to the torrent's collection of peers
            return self.peer_dicts[info_hash][contact]
        else:
            p = Peer(info_hash, peer_id, ip, port)
            # assign the new peer to the torrent's collection
            self.peer_dicts[info_hash][contact] = p
            # also add it to the 'global' list of peers known for the IP/port
            if contact in self.peers_by_ips:
                self.peers_by_ips[contact].append(p)
            else:
                self.peers_by_ips[contact] = [p]
            # we might know a node residing on the same address
            if contact in self.dht_nodes_by_ips:
                node = self.dht_nodes_by_ips[contact]
                if p.own_dht_node is not None and p.own_dht_node != node:
                    print(f"warning: overwriting associated node for peer {peer_id}")
                p.own_dht_node = node

            return p

    def extract_nodes(self, compact_node_list):
        num_nodes = len(compact_node_list) // 26
        for i in range(num_nodes):
            block_start = i * 26
            block_end = block_start + 26

            # Extract the 20-byte block and IPv4 address/port
            block = compact_node_list[block_start:block_start + 20]
            ip_port_bytes = compact_node_list[block_start + 20:block_end]

            # Unpack the IPv4 address and port using the 'struct' module
            ip_bytes, port = struct.unpack('!4sH', ip_port_bytes)
            ip_addr = '.'.join(str(b) for b in ip_bytes)

            self.get_or_add_node(block, ip_addr, port)

    def extract_peers(self, info_hash, dht_node, peer_list):
        for peer_contact in peer_list:
            # unpack the next 6 bytes into a tuple of 4-byte IP address and 2-byte port
            ip_bytes, port = struct.unpack('!4sH', peer_contact)
            ip_addr = '.'.join(str(b) for b in ip_bytes)
            p = self.get_or_add_peer(info_hash, ip_addr, port)
            if dht_node is not None:
                dht_node.add_known_peer(info_hash, p)

    def trace_btp(self, payload):
        pass

    def trace_dns(self, packet):
        if DNSRR not in packet:
            return

        name: bytes = packet[DNSRR].rrname
        val: str = packet[DNSRR].rdata
        if b'torrent' in name or b'dht' in name:
            self.dns_possible_dht[val] = name.decode()
        if b'torrent' in name or b'tracker' in name:
            self.dns_possible_trackers[val] = name.decode()

    def trace_udp_tracker_proto(self, payload):
        pass


class OutputManager(object):
    no_node_id_msg = 'no response, node ID not known          '

    def __init__(self, monitor: Monitor):
        self.monitor = monitor

    def report_bootstrap_node(self, node: DHTNode):
        n = self._get_bootstrap_node(node)

        print(
            f"{n['ip']}\t{n['port']}"
            f"\t{n['node_id'] if n['node_id'] is not None else OutputManager.no_node_id_msg}"
            f"\t{n['hostname_capture'] or '-'}\t{n['hostname_query'] or '-'}")

    def _get_bootstrap_node(self, node: DHTNode):
        hostname_c = self.monitor.dns_possible_dht[node.ip][:-1] if node.ip in self.monitor.dns_possible_dht else None
        try:
            query = socket.gethostbyaddr(node.ip)
            hostname_q = query[0] if query is not None and query[0] is not None else None
        except socket.herror:
            hostname_q = None

        return {'node_id': node.node_id.hex() if node.node_id is not None else None,
                'hostname_capture': hostname_c, 'hostname_query': hostname_q, 'ip': node.ip, 'port': node.port}


if __name__ == '__main__':
    print("dejte si kávičku, za chvíli jsem hotová\n")

    m = Monitor()

    # m.trace_udp_pcapng("../01 first run.pcapng")
    m.trace_udp_pcapng("../05 arch down 1.pcapng")
    for n in m.dht_bootstrap_nodes:
        m.out.report_bootstrap_node(n)
