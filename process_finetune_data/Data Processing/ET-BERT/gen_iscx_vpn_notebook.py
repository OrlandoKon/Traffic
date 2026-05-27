"""
生成 iscx_vpn_experiment_preprocess.ipynb
运行: /root/.local/share/mamba/envs/etbert/bin/python gen_iscx_vpn_notebook.py
"""
import json, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'iscx_vpn_experiment_preprocess.ipynb')

def code(src): return {'cell_type':'code','id':f'c{abs(hash(src))}','metadata':{},'outputs':[],'source':src}
def md(src):   return {'cell_type':'markdown','id':f'm{abs(hash(src))}','metadata':{},'source':src}

# ── cell sources ─────────────────────────────────────────────────────────────

MD0 = """\
# ISCX-VPN-2016 → ET-BERT 实验预处理（App 分类）

生成 **Group 0 / 1 / 2 / 3** 四组数据，任务：**App（16 类）**，3 个随机种子，packet-level 与 flow-level 各一份。

输出：`/root/Repository/Traffic/code/ET-BERT/outputs/group{0-3}/app/{pkt,flow}/split_{0-2}/{train,val,test}.tsv`

| Group | 描述 |
|-------|------|
| 0 | ET-BERT 论文设置：去 Ethernet+IP 头，跳过 4 字节端口（仅 TCP/UDP） |
| 1 | 保留 IP 头，仅留可用特征，其余置零 |
| 2 | Group 1 + 可能可用特征（TCP Seq/Ack/Options、部分 TLS 扩展） |
| 3 | 保留全部，仅置零捷径特征（IP 地址/端口/Window 等） |
"""

C1 = """\
import os, struct, binascii, csv, logging, random
from collections import defaultdict
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

_log_dir = '/root/Repository/Traffic/code/ET-BERT/logs'
os.makedirs(_log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(_log_dir, 'iscx_vpn_preprocess.log'), mode='w'),
        logging.StreamHandler(),
    ],
    force=True,
)
logger = logging.getLogger()
logger.info('Imports OK')
"""

C2 = """\
PCAP_ROOT   = '/root/data/ISCX-VPN-2016/pcap'
OUTPUT_ROOT = '/root/Repository/Traffic/code/ET-BERT/datasets/ISCX-VPN-2016'
os.makedirs(OUTPUT_ROOT, exist_ok=True)

SEEDS               = [42, 123, 456]
TRAIN_RATIO         = 0.8
VAL_RATIO           = 0.1
MAX_FLOWS_PER_CLASS = 2400
FIRST_N_PKTS        = 5      # m=5 packets per flow
PAYLOAD_LEN         = 128    # n=128 bigram tokens
GROUPS              = [0, 1, 2, 3]
"""

C3 = """\
# App classification: one class per app folder (16 classes, VPN+non-VPN merged)
APP_CLASSES     = sorted(d for d in os.listdir(PCAP_ROOT)
                         if os.path.isdir(os.path.join(PCAP_ROOT, d)))
APP_CLASS_TO_ID = {c: i for i, c in enumerate(APP_CLASSES)}

print(f'App classes ({len(APP_CLASSES)}):', APP_CLASSES)
"""

C4 = """\
# ── Flow extraction ──────────────────────────────────────────────────────────

def is_unwanted(pkt) -> bool:
    if pkt.haslayer(scapy.ARP):
        return True
    if pkt.haslayer(UDP):
        s, d = pkt[UDP].sport, pkt[UDP].dport
        if s in (67, 68) or d in (67, 68):
            return True
    return False


def flow_key(pkt):
    \"\"\"Directional 5-tuple key — matches Scapy PacketList.sessions() default.

    ET-BERT uses scapy's `packets.sessions()` which produces a session per
    (src_ip, src_port, dst_ip, dst_port, proto) without canonicalization,
    so A→B and B→A end up as two separate sessions.\"\"\"
    if pkt.haslayer(IP):
        s, d, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
    elif pkt.haslayer(IPv6):
        s, d, proto = pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
    else:
        return None
    sp = dp = 0
    if pkt.haslayer(TCP):
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
    return (s, sp, d, dp, proto)


def extract_flows_from_pcap(pcap_path: str) -> dict:
    \"\"\"5-tuple flow extraction (matches ET-BERT / scapy sessions()).

    One flow == one directional 5-tuple. No SYN/RST splitting, no UDP timeout.
    Returns {flow_key: [raw_bytes, ...]}.\"\"\"
    flows = defaultdict(list)
    try:
        for pkt in scapy.PcapReader(pcap_path):
            if is_unwanted(pkt):
                continue
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                continue
            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue
            k = flow_key(pkt)
            if k is None:
                continue
            raw = bytes(pkt)
            if not pkt.haslayer(scapy.Ether):
                ver = raw[0] >> 4 if raw else 0
                et = b'\\x08\\x00' if ver == 4 else b'\\x86\\xdd'
                raw = b'\\x00' * 12 + et + raw
            flows[k].append(raw)
    except Exception as e:
        logger.warning(f'Error reading {pcap_path}: {e}')
    return dict(flows)
"""

# Cell 5: IPv6 extension-header helper + Group 0 masking
C5 = """\
# ── IPv6 extension-header chain parser ───────────────────────────────────────
# RFC 8200: extension headers that carry their own length field.
# Fragment header (44) is always exactly 8 bytes.
# ESP (50) is variable-length and opaque; we stop there.
_IPV6_EXT_HDRS = frozenset({
    0,   # Hop-by-Hop Options
    43,  # Routing
    44,  # Fragment (fixed 8 B)
    51,  # Authentication Header (AH)
    60,  # Destination Options
    135, # Mobility Header
    139, # Host Identity Protocol
    140, # Shim6 Protocol
})

def _ipv6_transport(buf, ipv6_off: int):
    \"\"\"
    Walk the IPv6 fixed header + any extension headers.
    Returns (transport_offset, transport_proto).
    buf may be bytes or bytearray.
    \"\"\"
    if ipv6_off + 40 > len(buf):
        return len(buf), 0
    next_hdr = buf[ipv6_off + 6]
    off = ipv6_off + 40
    while next_hdr in _IPV6_EXT_HDRS:
        if off + 2 > len(buf):
            return len(buf), 0
        if next_hdr == 44:              # Fragment header: exactly 8 bytes
            hdr_len = 8
        else:                           # Generic: (hdr_ext_len + 1) * 8
            hdr_len = (buf[off + 1] + 1) * 8
        next_hdr = buf[off]
        off += hdr_len
    return off, next_hdr


# ── Group 0: ET-BERT baseline masking ────────────────────────────────────────

def mask_group0(raw: bytes) -> bytes:
    \"\"\"
    Strip Ethernet header + IP/IPv6 header (incl. IPv6 extension headers).
    Then skip src_port + dst_port (4 B) only for TCP (6) or UDP (17).
    \"\"\"
    if len(raw) < 14:
        return b''

    ether_type = struct.unpack('!H', raw[12:14])[0]
    ip_off = 14
    if ether_type == 0x8100 and ip_off + 4 <= len(raw):   # 802.1Q VLAN tag
        ether_type = struct.unpack('!H', raw[ip_off+2:ip_off+4])[0]
        ip_off += 4

    if ether_type == 0x0800:                               # IPv4
        if ip_off + 20 > len(raw):
            return b''
        ihl    = (raw[ip_off] & 0x0F) * 4
        proto  = raw[ip_off + 9]
        tr_off = ip_off + ihl
    elif ether_type == 0x86DD:                             # IPv6
        tr_off, proto = _ipv6_transport(raw, ip_off)
    else:
        return b''

    if tr_off >= len(raw):
        return b''

    # Skip src_port (2 B) + dst_port (2 B) only for TCP / UDP
    if proto in (6, 17):
        tr_off += 4

    return raw[tr_off:] if tr_off < len(raw) else b''
"""

# Cell 6: IPv4/IPv6 header masking for Groups 1/2/3
C6 = """\
# ── IPv4 / IPv6 header masking (Groups 1/2/3) ────────────────────────────────

def mask_ipv4_header(buf: bytearray, off: int, group: int):
    \"\"\"Mask IPv4 header in-place. Returns (transport_offset, proto).\"\"\"
    if off + 20 > len(buf):
        return len(buf), 0
    ihl   = max(20, (buf[off] & 0x0F) * 4)
    proto = buf[off + 9]

    if group in (1, 2):
        buf[off]          &= 0x0F                    # keep IHL, zero Version
        buf[off+4]         = buf[off+5] = 0          # Identification
        buf[off+6]         = buf[off+6] & 0x40       # keep DF bit only
        buf[off+7]         = 0                       # Fragment Offset low
        buf[off+8]         = 0                       # TTL
        buf[off+10]        = buf[off+11] = 0         # Header Checksum
        buf[off+12:off+16] = b'\\x00' * 4            # Source IP
        buf[off+16:off+20] = b'\\x00' * 4            # Destination IP
        if ihl > 20:
            buf[off+20:off+ihl] = b'\\x00' * (ihl - 20)  # Options

    elif group == 3:
        buf[off+12:off+16] = b'\\x00' * 4            # Source IP (shortcut)
        buf[off+16:off+20] = b'\\x00' * 4            # Destination IP (shortcut)

    return off + ihl, proto


def mask_ipv6_header(buf: bytearray, off: int, group: int):
    \"\"\"
    Mask IPv6 fixed header (40 B) in-place, then walk extension headers
    to find the actual transport layer.
    Returns (transport_offset, transport_proto).
    \"\"\"
    if off + 40 > len(buf):
        return len(buf), 0

    if group in (1, 2):
        buf[off:off+4]     = b'\\x00' * 4            # Version + TC + Flow Label
        buf[off+7]         = 0                       # Hop Limit
        buf[off+8:off+24]  = b'\\x00' * 16           # Source Address
        buf[off+24:off+40] = b'\\x00' * 16           # Destination Address

    elif group == 3:
        buf[off+7]         = 0                       # Hop Limit (shortcut)
        buf[off+8:off+24]  = b'\\x00' * 16           # Source Address
        buf[off+24:off+40] = b'\\x00' * 16           # Destination Address

    # Walk extension header chain to find true transport offset + protocol
    return _ipv6_transport(buf, off)
"""

C7 = """\
# ── TCP / UDP header masking (Groups 1/2/3) ──────────────────────────────────

def mask_tcp_header(buf: bytearray, off: int, group: int) -> int:
    \"\"\"Mask TCP header in-place. Returns payload start offset.\"\"\"
    if off + 20 > len(buf):
        return len(buf)
    doff_bytes = max(20, (buf[off + 12] >> 4) * 4)
    tcp_end    = min(off + doff_bytes, len(buf))

    if group in (1, 2):
        buf[off]    = buf[off+1] = 0                 # Source Port
        buf[off+2]  = buf[off+3] = 0                 # Destination Port
        if group == 1:
            buf[off+4:off+12] = b'\\x00' * 8         # Seq + Ack (G1 zeroes)
        # G2 keeps Seq / Ack / Options
        buf[off+12] = 0                              # Data Offset + Reserved
        # Flags [7=CWR|6=ECE|5=URG|4=ACK|3=PSH|2=RST|1=SYN|0=FIN]
        flags = buf[off+13]
        if group == 1:
            buf[off+13] = flags & 0x0F               # keep PSH/RST/SYN/FIN
        else:
            buf[off+13] = flags & 0xCF               # keep CWR/ECE + PSH/RST/SYN/FIN
        buf[off+14] = buf[off+15] = 0                # Window
        buf[off+16] = buf[off+17] = 0                # Checksum
        buf[off+18] = buf[off+19] = 0                # Urgent Pointer
        if group == 1 and doff_bytes > 20:           # Options (G1 zeroes)
            buf[off+20:tcp_end] = b'\\x00' * (tcp_end - off - 20)

    elif group == 3:
        buf[off]    = buf[off+1] = 0                 # Source Port (shortcut)
        buf[off+2]  = buf[off+3] = 0                 # Destination Port (shortcut)
        buf[off+12] &= 0x0F                          # Data Offset: zero high nibble
        buf[off+14]  = buf[off+15] = 0               # Window (shortcut)

    return tcp_end


def mask_udp_header(buf: bytearray, off: int, group: int) -> int:
    \"\"\"Mask UDP header in-place. Returns payload start offset.\"\"\"
    if off + 8 > len(buf):
        return len(buf)
    if group in (1, 2):
        buf[off]   = buf[off+1] = 0                  # Source Port
        buf[off+2] = buf[off+3] = 0                  # Destination Port
        buf[off+6] = buf[off+7] = 0                  # Checksum
    elif group == 3:
        buf[off]   = buf[off+1] = 0                  # Source Port (shortcut)
        buf[off+2] = buf[off+3] = 0                  # Destination Port (shortcut)
    return off + 8
"""

C8 = """\
# ── TLS field masking (Groups 1/2/3) ─────────────────────────────────────────

TLS_EXT_SNI        = 0x0000
TLS_EXT_ALPN       = 0x0010
TLS_EXT_SUP_GROUPS = 0x000a
TLS_EXT_SIG_ALGOS  = 0x000d
TLS_EXT_SUP_VERS   = 0x002b
TLS_EXT_PSK_KEX    = 0x002d
TLS_EXT_PRE_SHARED = 0x0029

_CH_KEEP = {
    1: frozenset({TLS_EXT_ALPN}),
    2: frozenset({TLS_EXT_ALPN, TLS_EXT_SUP_VERS, TLS_EXT_SUP_GROUPS,
                  TLS_EXT_SIG_ALGOS, TLS_EXT_PSK_KEX}),
}
_SH_KEEP = {
    1: frozenset(),
    2: frozenset({TLS_EXT_SUP_VERS, TLS_EXT_PRE_SHARED}),
}


def _ext_iter(buf, ext_start, ext_end):
    pos = ext_start
    while pos + 4 <= ext_end:
        etype = struct.unpack('!H', bytes(buf[pos:pos+2]))[0]
        elen  = struct.unpack('!H', bytes(buf[pos+2:pos+4]))[0]
        size  = 4 + elen
        if pos + size > ext_end:
            break
        yield pos, etype, size
        pos += size


def _mask_ext_keep(buf, s, e, keep):
    for pos, etype, size in list(_ext_iter(buf, s, e)):
        if etype not in keep:
            buf[pos:pos+size] = b'\\x00' * size


def _mask_ext_zero(buf, s, e, zero_set):
    for pos, etype, size in list(_ext_iter(buf, s, e)):
        if etype in zero_set:
            buf[pos:pos+size] = b'\\x00' * size


def _mask_client_hello(buf, start, end, group):
    pos = start
    if pos + 34 > end:
        return
    if group in (1, 2):
        buf[pos:pos+2] = b'\\x00\\x00'               # Legacy Version
    pos += 2
    if group in (1, 2):
        buf[pos:pos+32] = b'\\x00' * 32              # Random
    pos += 32
    if pos >= end:
        return
    sid_len = buf[pos]
    if group in (1, 2):
        buf[pos] = 0
    pos += 1
    if pos + sid_len > end:
        return
    if group in (1, 2):
        buf[pos:pos+sid_len] = b'\\x00' * sid_len
    pos += sid_len
    if pos + 2 > end:
        return
    cs_len = struct.unpack('!H', bytes(buf[pos:pos+2]))[0]
    buf[pos:pos+2+cs_len] = b'\\x00' * (2 + cs_len)  # Cipher Suites (all groups)
    pos += 2 + cs_len
    if pos >= end:
        return
    cm_len = buf[pos]
    if group in (1, 2):
        buf[pos:pos+1+cm_len] = b'\\x00' * (1 + cm_len)  # Compression Methods
    pos += 1 + cm_len
    if pos + 2 > end:
        return
    exts_len = struct.unpack('!H', bytes(buf[pos:pos+2]))[0]
    ext_s = pos + 2
    ext_e = min(ext_s + exts_len, end)
    if group in (1, 2):
        _mask_ext_keep(buf, ext_s, ext_e, _CH_KEEP[group])
    elif group == 3:
        _mask_ext_zero(buf, ext_s, ext_e, {TLS_EXT_SNI})


def _mask_server_hello(buf, start, end, group):
    pos = start
    if pos + 34 > end:
        return
    if group in (1, 2):
        buf[pos:pos+2] = b'\\x00\\x00'               # Legacy Version
    pos += 2
    if group in (1, 2):
        buf[pos:pos+32] = b'\\x00' * 32              # Random
    pos += 32
    if pos >= end:
        return
    sid_len = buf[pos]
    if group in (1, 2):
        buf[pos] = 0
    pos += 1
    if pos + sid_len > end:
        return
    if group in (1, 2):
        buf[pos:pos+sid_len] = b'\\x00' * sid_len
    pos += sid_len
    if pos + 2 > end:
        return
    buf[pos:pos+2] = b'\\x00\\x00'                   # Cipher Suite (shortcut, all groups)
    pos += 2
    if pos >= end:
        return
    if group in (1, 2):
        buf[pos] = 0                                 # Compression Method
    pos += 1
    if pos + 2 > end:
        return
    exts_len = struct.unpack('!H', bytes(buf[pos:pos+2]))[0]
    ext_s = pos + 2
    ext_e = min(ext_s + exts_len, end)
    if group in (1, 2):
        _mask_ext_keep(buf, ext_s, ext_e, _SH_KEEP[group])


def mask_tls_payload(buf: bytearray, tls_start: int, group: int):
    pos = tls_start
    while pos + 5 <= len(buf):
        ct  = buf[pos]
        ver = struct.unpack('!H', bytes(buf[pos+1:pos+3]))[0]
        if ct not in (20, 21, 22, 23) or ver not in (0x0301, 0x0302, 0x0303, 0x0304):
            break
        rec_len = struct.unpack('!H', bytes(buf[pos+3:pos+5]))[0]
        rec_end = pos + 5 + rec_len
        if rec_end > len(buf):
            break
        if group in (1, 2):
            buf[pos+1:pos+3] = b'\\x00\\x00'          # Record Legacy Version
        if ct == 22:                                  # Handshake
            hp = pos + 5
            while hp + 4 <= rec_end:
                hs_type = buf[hp]
                hs_len  = struct.unpack('!I', b'\\x00' + bytes(buf[hp+1:hp+4]))[0]
                hs_s, hs_e = hp + 4, hp + 4 + hs_len
                if hs_e > rec_end:
                    break
                if hs_type == 1:
                    _mask_client_hello(buf, hs_s, hs_e, group)
                elif hs_type == 2:
                    _mask_server_hello(buf, hs_s, hs_e, group)
                hp = hs_e
        elif ct == 23:                                # Application Data: zero ciphertext
            buf[pos+5:rec_end] = b'\\x00' * rec_len
        pos = rec_end
"""

C9 = """\
# ── Main masking dispatcher ──────────────────────────────────────────────────

def _looks_like_tls(data: bytes) -> bool:
    if len(data) < 5:
        return False
    ct  = data[0]
    ver = struct.unpack('!H', data[1:3])[0]
    return ct in (20, 21, 22, 23) and ver in (0x0301, 0x0302, 0x0303, 0x0304)


def apply_mask(raw: bytes, group: int) -> bytes:
    \"\"\"
    Apply field masking; return bytes for ET-BERT input.

    Group 0 : strip Ethernet+IP+ports (ET-BERT baseline), full payload included.
    Groups 1-3 (header-only mode):
      TCP + TLS  : mask TLS fields per group, zero App Data ciphertext;
                   return IP+TCP headers + full TLS record structure.
      TCP + other: return IP+TCP headers only (no payload).
      UDP        : return IP+UDP headers only (no payload).
      Other proto: return IP header only.
    \"\"\"
    if group == 0:
        return mask_group0(raw)
    if len(raw) < 14:
        return b''

    buf = bytearray(raw)
    ether_type = struct.unpack('!H', bytes(buf[12:14]))[0]
    ip_off = 14
    if ether_type == 0x8100 and ip_off + 4 <= len(buf):   # VLAN
        ether_type = struct.unpack('!H', bytes(buf[ip_off+2:ip_off+4]))[0]
        ip_off += 4

    if ether_type == 0x0800:
        tr_off, proto = mask_ipv4_header(buf, ip_off, group)
    elif ether_type == 0x86DD:
        tr_off, proto = mask_ipv6_header(buf, ip_off, group)
    else:
        return b''

    if tr_off >= len(buf):
        return bytes(buf[ip_off:])

    if proto == 6:    # TCP
        pl_off = mask_tcp_header(buf, tr_off, group)
        if pl_off < len(buf) and _looks_like_tls(bytes(buf[pl_off:pl_off+5])):
            mask_tls_payload(buf, pl_off, group)   # App Data bodies zeroed in-place
            return bytes(buf[ip_off:])             # include TLS structure
        return bytes(buf[ip_off:pl_off])           # non-TLS: headers only

    elif proto == 17: # UDP
        pl_off = mask_udp_header(buf, tr_off, group)
        return bytes(buf[ip_off:pl_off])           # always headers only

    return bytes(buf[ip_off:tr_off])               # other proto: IP header only
"""

C10 = """\
# ── ET-BERT feature generation (identical to original notebook) ──────────────

def bigram_generation(hex_str: str, packet_len: int = 128) -> str:
    \"\"\"Sliding-window hex bigram tokenisation.\"\"\"
    tokens, count = [], 0
    for i in range(len(hex_str) - 1):
        count += 1
        if count > packet_len:
            break
        tokens.append(hex_str[i] + hex_str[i+1])
    return ' '.join(tokens)


def packet_to_feature(raw: bytes, group: int) -> str:
    masked = apply_mask(raw, group)
    if not masked:
        return ''
    return bigram_generation(binascii.hexlify(masked).decode(), PAYLOAD_LEN)
"""

C11 = """\
# ── Load all flows from raw PCAP files ───────────────────────────────────────

def load_all_flows() -> dict:
    \"\"\"Returns {app_name: [[pkt_bytes, ...], ...]}\"\"\"
    app_flows: dict = defaultdict(list)

    for app in APP_CLASSES:
        app_dir    = os.path.join(PCAP_ROOT, app)
        pcap_files = sorted(f for f in os.listdir(app_dir)
                            if f.lower().endswith(('.pcap', '.pcapng')))
        for fname in pcap_files:
            fpath = os.path.join(app_dir, fname)
            logger.info(f'Reading {fpath}')
            for pkts in extract_flows_from_pcap(fpath).values():
                if len(pkts) < 3:   # mirror ET-BERT's get_feature_flow minimum
                    continue
                app_flows[app].append(pkts[:FIRST_N_PKTS])

    counts = {k: len(v) for k, v in app_flows.items()}
    logger.info('Flow counts: ' + str(counts))
    return dict(app_flows)


logger.info('Loading flows — may take several minutes ...')
app_flows = load_all_flows()
logger.info('Done loading.')
"""

C12 = """\
# ── Flow-based 8:1:1 split ───────────────────────────────────────────────────

def split_flows(class_flows: dict, class_to_id: dict, seed: int):
    rng = random.Random(seed)
    train, val, test = [], [], []

    for cls_name in sorted(class_to_id):
        cls_id = class_to_id[cls_name]
        flows  = list(class_flows.get(cls_name, []))
        if not flows:
            logger.warning(f'No flows: {cls_name}')
            continue
        if len(flows) > MAX_FLOWS_PER_CLASS:
            flows = rng.sample(flows, MAX_FLOWS_PER_CLASS)
        rng.shuffle(flows)
        n      = len(flows)
        n_val  = max(1, int(n * VAL_RATIO))
        n_test = max(1, int(n * (1 - TRAIN_RATIO - VAL_RATIO)))
        n_train = n - n_val - n_test

        train.extend([(cls_id, f) for f in flows[:n_train]])
        val.extend(  [(cls_id, f) for f in flows[n_train:n_train+n_val]])
        test.extend( [(cls_id, f) for f in flows[n_train+n_val:]])

    return train, val, test
"""

C13 = """\
# ── TSV save + pipeline ───────────────────────────────────────────────────────

def save_tsv(samples, group: int, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = [['label', 'text_a']]
    for cls_id, flow_pkts in samples:
        parts = [packet_to_feature(raw, group) for raw in flow_pkts]
        feat  = ' '.join(p for p in parts if p).strip()
        if feat:
            rows.append([cls_id, feat])
    with open(path, 'w', newline='') as f:
        csv.writer(f, delimiter='\\t').writerows(rows)
    logger.info(f'  -> {path}  ({len(rows)-1} samples)')


def run_pipeline(class_flows: dict, class_to_id: dict):
    for si, seed in enumerate(SEEDS):
        logger.info(f'seed {si} (={seed})')
        train, val, test = split_flows(class_flows, class_to_id, seed)
        logger.info(f'  train={len(train)}  val={len(val)}  test={len(test)}')

        for group in GROUPS:
            base = os.path.join(OUTPUT_ROOT, f'group_{group}', f'split_{si}')
            for name, data in [('train', train), ('val', val), ('test', test)]:
                save_tsv(data, group, os.path.join(base, f'{name}.tsv'))

        logger.info(f'seed {si} done.')
    logger.info(f'=== finished. Output: {OUTPUT_ROOT} ===')
"""

C14 = """\
run_pipeline(app_flows, APP_CLASS_TO_ID)
"""

# ── Assemble ─────────────────────────────────────────────────────────────────

cells = [md(MD0), code(C1), code(C2), code(C3), code(C4),
         code(C5), code(C6), code(C7), code(C8), code(C9),
         code(C10), code(C11), code(C12), code(C13), code(C14)]

nb = {
    'nbformat': 4,
    'nbformat_minor': 5,
    'metadata': {
        'kernelspec': {'display_name': 'etbert', 'language': 'python', 'name': 'etbert'},
        'language_info': {'name': 'python'},
    },
    'cells': cells,
}

with open(OUT, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'Written: {OUT}')
