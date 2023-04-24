#!/usr/bin/env python3
# bt-monitor.py
# Author: Ondřej Ondryáš (xondry02@stud.fit.vut.cz)
import sys
import struct

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, defragment, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapNgReader
from bencoder import bdecode2, BTFailure


class Peer:
    def __init__(self, info_hash, peer_id, ip, port, dht_node):
        self.info_hash = info_hash
        self.dht_node = dht_node
        self.port = port
        self.ip = ip
        self.peer_id = peer_id


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

        for n in nodes:
            self.known_nodes[info_hash].append(n)

    def add_known_peers(self, info_hash, peers):
        if info_hash not in self.known_peers:
            self.known_peers[info_hash] = []

        for p in peers:
            self.known_peers[info_hash].append(p)


class Monitor:

    def __init__(self):
        self.dns_possible_dht = {}
        self.dns_possible_trackers = {}
        self.dht_transactions = {}

        self.peer_dicts = {}
        self.dht_bootstrap_nodes = []
        self.dht_nodes = []
        self.dht_nodes_by_ips = {}
        self.dht_known_ips = []

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
            return self.dht_transactions[key_cand]
        key_cand = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, trans_id)
        if key_cand in self.dht_transactions:
            return self.dht_transactions[key_cand]

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

    def get_or_add_node(self, ip, port):
        contact = (ip, port)
        if contact in self.dht_nodes_by_ips:
            node = self.dht_nodes_by_ips[contact]
            return node, True
        else:
            node = DHTNode(None, ip, port)
            self.dht_nodes.append(node)
            self.dht_nodes_by_ips[contact] = node
            return node, False

    def trace_dht_req(self, packet, decoded):
        req_type = decoded[b'q']
        args = decoded[b'a']

        if b'info_hash' not in args:
            return

        i_hash = args[b'info_hash']
        node, had_contact = self.get_or_add_node(packet[IP].dst, packet[UDP].dport)

        if req_type == b'get_peers':
            if b't' in decoded:
                self.set_dht_flow(packet, decoded[b't'], (node, i_hash))
            if not had_contact:
                self.dht_bootstrap_nodes.append(node)
        elif req_type == b'announce_peer':
            p = self.get_or_add_peer(i_hash, packet[IP].src, packet[UDP].sport, node)
            node.add_known_peers(i_hash, [p])

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
                print(f"node id mismatch, prev: {node.node_id}, now got in response: {node_id}")

            node.node_id = node_id
            if b'values' in resp:
                self.extract_peers(i_hash, node, resp[b'values'])

            if b'nodes' in resp:
                self.extract_nodes(resp[b'nodes'])

    def get_or_add_peer(self, info_hash, ip, port, dht_node=None, peer_id=None):
        if info_hash not in self.peer_dicts:
            self.peer_dicts[info_hash] = {}

        if (ip, port) in self.peer_dicts[info_hash]:
            return self.peer_dicts[info_hash][(ip, port)]
        else:
            p = Peer(info_hash, peer_id, ip, port, dht_node)
            self.peer_dicts[info_hash][(ip, port)] = p
            return p

    def extract_nodes(self, compact_node_list):
        num_nodes = len(compact_node_list) // 26
        nodes = []
        for i in range(num_nodes):
            block_start = i * 26
            block_end = block_start + 26

            # Extract the 20-byte block and IPv4 address/port
            block = compact_node_list[block_start:block_start + 20]
            ip_port_bytes = compact_node_list[block_start + 20:block_end]

            # Unpack the IPv4 address and port using the 'struct' module
            ip_bytes, port = struct.unpack('!4sH', ip_port_bytes)
            ip_addr = '.'.join(str(b) for b in ip_bytes)

            self.get_or_add_node(ip_addr, port)

    def extract_peers(self, info_hash, dht_node, compact_peer_list):
        num_addresses = len(compact_peer_list) // 6
        for i in range(num_addresses):
            # unpack the next 6 bytes into a tuple of 4-byte IP address and 2-byte port
            ip_bytes, port = struct.unpack('!4sH', compact_peer_list[i * 6:(i + 1) * 6])
            ip_addr = '.'.join(str(b) for b in ip_bytes)
            self.get_or_add_peer(info_hash, ip_addr, port, dht_node)

    def trace_btp(self, payload):
        pass

    def trace_dns(self, packet):
        if DNSRR not in packet:
            return

        name: bytes = packet[DNSRR].rrname
        val: bytes = packet[DNSRR].rdata
        if b'torrent' in name or b'dht' in name:
            self.dns_possible_dht[val] = name.decode()
        if b'torrent' in name or b'tracker' in name:
            self.dns_possible_trackers[val] = name

    def trace_udp_tracker_proto(self, payload):
        pass

    def get_bootstrap_nodes(self):
        import socket

        for x in self.dht_bootstrap_nodes:
            hostname_c = self.dns_possible_dht[x.ip][:-1] if x.ip in self.dns_possible_dht else None
            try:
                query = socket.gethostbyaddr(x.ip)
                hostname_q = query[0] if query is not None and query[0] is not None else None
            except socket.herror:
                hostname_q = None

            yield {'node_id': x.node_id.hex() if x.node_id is not None else None,
                   'hostname_capture': hostname_c, 'hostname_query': hostname_q, 'ip': x.ip, 'port': x.port}


if __name__ == '__main__':
    m = Monitor()
    m.trace_udp_pcapng(sys.argv[1])

    print("Bootstrap nodes:")
    no_node_id_msg = 'no response, node ID not known          '

    for n in m.get_bootstrap_nodes():
        print(
            f"{n['ip']}\t{n['port']}"
            f"\t{n['node_id'] if n['node_id'] is not None else no_node_id_msg}"
            f"\t{n['hostname_capture'] or '-'}\t{n['hostname_query'] or '-'}")
