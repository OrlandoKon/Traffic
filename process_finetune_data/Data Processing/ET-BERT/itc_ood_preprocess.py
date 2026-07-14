# encoding=utf-8
"""
ITC-Net-Blend-60 -> ET-BERT OoD preprocessing.

This script follows the TrafficCOGS ITC setup as closely as possible:
  - input flows are the TrafficCOGS segmented flows
    (/root/Repository/TrafficCOGS/dataset/itcnet60/flows)
  - five scenarios: Scenario_A ... Scenario_E
  - label space is the intersection of classes across all five scenarios
  - leave-one-scenario-out folds
  - first 5 packets per flow
  - per-scenario/per-class max 500 flows
  - packets are parsed from the IP layer, matching TrafficCOGS arrays

Shortcut removal is mandatory here:
  - IPv4/IPv6 source and destination addresses are zeroed
  - TCP/UDP source and destination ports are zeroed
  - TLS ClientHello SNI extension is zeroed

Output:
  /root/Repository/Traffic/code/ET-BERT/datasets/ITC-Net-Blend-60/
      fold_A/{train,val,test}.tsv
      ...
      fold_E/{train,val,test}.tsv

Run:
  /root/.local/share/mamba/envs/etbert/bin/python itc_ood_preprocess.py
"""
import argparse
import binascii
import csv
import json
import logging
import random
import struct
from multiprocessing import Pool
from pathlib import Path

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


SCENARIOS = ["Scenario_A", "Scenario_B", "Scenario_C", "Scenario_D", "Scenario_E"]
DEFAULT_FLOWS_ROOT = Path("/root/Repository/TrafficCOGS/dataset/itcnet60/flows")
DEFAULT_OUTPUT_ROOT = Path("/root/Repository/Traffic/code/ET-BERT/datasets/ITC-Net-Blend-60")
LOG_DIR = Path("/root/Repository/Traffic/code/ET-BERT/logs")

TLS_EXT_SNI = 0x0000
IPV6_EXT_HDRS = frozenset({
    0,    # Hop-by-Hop Options
    43,   # Routing
    44,   # Fragment
    51,   # Authentication Header
    60,   # Destination Options
    135,  # Mobility
    139,  # HIP
    140,  # Shim6
})


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "itc_ood_preprocess.log", mode="w"),
            logging.StreamHandler(),
        ],
        force=True,
    )


def u16(buf, off):
    return struct.unpack("!H", bytes(buf[off:off + 2]))[0]


def common_classes(flows_root):
    sets = []
    for scenario in SCENARIOS:
        sdir = flows_root / scenario
        if not sdir.exists():
            raise FileNotFoundError(f"Missing scenario directory: {sdir}")
        sets.append({p.name for p in sdir.iterdir() if p.is_dir()})
    return sorted(set.intersection(*sets))


def ipv6_transport(buf, off):
    if off + 40 > len(buf):
        return len(buf), 0
    next_hdr = buf[off + 6]
    pos = off + 40
    while next_hdr in IPV6_EXT_HDRS:
        if pos + 2 > len(buf):
            return len(buf), 0
        hdr_len = 8 if next_hdr == 44 else (buf[pos + 1] + 1) * 8
        next_hdr = buf[pos]
        pos += hdr_len
    return pos, next_hdr


def zero_tls_sni(buf, tls_start):
    """Zero TLS ClientHello SNI extension TLV in-place."""
    pos = tls_start
    n = len(buf)
    while pos + 5 <= n:
        content_type = buf[pos]
        version = u16(buf, pos + 1)
        if content_type not in (20, 21, 22, 23) or version not in (0x0301, 0x0302, 0x0303, 0x0304):
            break
        rec_len = u16(buf, pos + 3)
        rec_end = pos + 5 + rec_len
        if rec_end > n:
            break

        if content_type == 22:
            hp = pos + 5
            while hp + 4 <= rec_end:
                hs_type = buf[hp]
                hs_len = struct.unpack("!I", b"\x00" + bytes(buf[hp + 1:hp + 4]))[0]
                hs_start = hp + 4
                hs_end = hs_start + hs_len
                if hs_end > rec_end:
                    break
                if hs_type == 1:
                    zero_client_hello_sni(buf, hs_start, hs_end)
                hp = hs_end

        if rec_len == 0:
            break
        pos = rec_end


def zero_client_hello_sni(buf, start, end):
    pos = start
    if pos + 34 > end:
        return
    pos += 2 + 32  # legacy_version + random
    if pos >= end:
        return
    session_id_len = buf[pos]
    pos += 1 + session_id_len
    if pos + 2 > end:
        return
    cipher_suites_len = u16(buf, pos)
    pos += 2 + cipher_suites_len
    if pos >= end:
        return
    compression_methods_len = buf[pos]
    pos += 1 + compression_methods_len
    if pos + 2 > end:
        return
    extensions_len = u16(buf, pos)
    ext_pos = pos + 2
    ext_end = min(ext_pos + extensions_len, end)

    while ext_pos + 4 <= ext_end:
        ext_type = u16(buf, ext_pos)
        ext_len = u16(buf, ext_pos + 2)
        ext_total = 4 + ext_len
        if ext_pos + ext_total > ext_end:
            break
        if ext_type == TLS_EXT_SNI:
            buf[ext_pos:ext_pos + ext_total] = b"\x00" * ext_total
        ext_pos += ext_total


def mask_shortcuts_ip_packet(raw_ip, packet_bytes):
    """Return IP-layer bytes with IP/ports/SNI removed."""
    if not raw_ip:
        return b""
    buf = bytearray(raw_ip)
    version = buf[0] >> 4

    if version == 4 and len(buf) >= 20:
        ihl = max(20, (buf[0] & 0x0F) * 4)
        proto = buf[9]
        buf[12:16] = b"\x00" * 4
        buf[16:20] = b"\x00" * 4
        transport_off = ihl
    elif version == 6 and len(buf) >= 40:
        proto = buf[6]
        buf[8:24] = b"\x00" * 16
        buf[24:40] = b"\x00" * 16
        transport_off, proto = ipv6_transport(buf, 0)
    else:
        return b""

    if proto == 6 and transport_off + 20 <= len(buf):
        buf[transport_off:transport_off + 4] = b"\x00" * 4
        data_offset = max(20, (buf[transport_off + 12] >> 4) * 4)
        payload_off = min(transport_off + data_offset, len(buf))
        zero_tls_sni(buf, payload_off)
    elif proto == 17 and transport_off + 8 <= len(buf):
        buf[transport_off:transport_off + 4] = b"\x00" * 4

    return bytes(buf[:packet_bytes])


def bigram_generation(hex_str, packet_len):
    tokens = []
    count = 0
    for i in range(len(hex_str) - 1):
        count += 1
        if count > packet_len:
            break
        tokens.append(hex_str[i] + hex_str[i + 1])
    return " ".join(tokens)


def packet_to_feature(raw_ip, packet_bytes, packet_bigrams):
    masked = mask_shortcuts_ip_packet(raw_ip, packet_bytes)
    if not masked:
        return ""
    hex_str = binascii.hexlify(masked).decode()
    return bigram_generation(hex_str, packet_bigrams)


def read_flow_feature(flow_pcap, first_n_pkts, packet_bytes, packet_bigrams, min_pkt_len):
    parts = []
    try:
        with scapy.PcapReader(str(flow_pcap)) as reader:
            for pkt in reader:
                if len(parts) >= first_n_pkts:
                    break
                if IP in pkt:
                    raw_ip = bytes(pkt[IP])
                elif IPv6 in pkt:
                    raw_ip = bytes(pkt[IPv6])
                else:
                    continue
                if len(raw_ip) < min_pkt_len:
                    continue
                feat = packet_to_feature(raw_ip, packet_bytes, packet_bigrams)
                if feat:
                    parts.append(feat)
    except Exception as exc:
        logging.warning("Failed reading %s: %s", flow_pcap, exc)
    return " ".join(parts).strip()


def collect_scenario_samples(flows_root, classes, class_to_id, max_flows, seed):
    rng = random.Random(seed)
    samples = {scenario: [] for scenario in SCENARIOS}
    counts = {scenario: {} for scenario in SCENARIOS}

    for scenario in SCENARIOS:
        for cls in classes:
            fps = sorted((flows_root / scenario / cls).glob("*.pcap"))
            if len(fps) > max_flows:
                fps = rng.sample(fps, max_flows)
                fps.sort()
            label = class_to_id[cls]
            samples[scenario].extend((label, fp) for fp in fps)
            counts[scenario][cls] = len(fps)
        logging.info("%s: %d sampled flows", scenario, len(samples[scenario]))
    return samples, counts


def split_train_val(samples_by_scenario, held, val_ratio, seed, valid_scenario=None):
    train_scenarios = [s for s in SCENARIOS if s != held]
    test = list(samples_by_scenario[held])

    if valid_scenario:
        if valid_scenario == held or valid_scenario not in SCENARIOS:
            raise ValueError(f"valid_scenario must be a non-held scenario, got {valid_scenario}")
        train = []
        val = list(samples_by_scenario[valid_scenario])
        for scenario in train_scenarios:
            if scenario != valid_scenario:
                train.extend(samples_by_scenario[scenario])
        return train, val, test

    by_label = {}
    for scenario in train_scenarios:
        for label, fp in samples_by_scenario[scenario]:
            by_label.setdefault(label, []).append((label, fp))

    rng = random.Random(seed)
    train, val = [], []
    for label in sorted(by_label):
        rows = list(by_label[label])
        rng.shuffle(rows)
        n_val = max(1, int(len(rows) * val_ratio))
        val.extend(rows[:n_val])
        train.extend(rows[n_val:])
    rng.shuffle(train)
    rng.shuffle(val)
    return train, val, test


def feature_job(job):
    flow_pcap, first_n_pkts, packet_bytes, packet_bigrams, min_pkt_len = job
    return flow_pcap, read_flow_feature(
        flow_pcap, first_n_pkts, packet_bytes, packet_bigrams, min_pkt_len
    )


def build_feature_cache(samples_by_scenario, args):
    flow_paths = sorted({
        str(fp)
        for rows in samples_by_scenario.values()
        for _, fp in rows
    })
    logging.info("precomputing %d unique flow features with %d workers", len(flow_paths), args.workers)
    jobs = [
        (fp, args.first_n_pkts, args.packet_bytes, args.packet_bigrams, args.min_pkt_len)
        for fp in flow_paths
    ]
    cache = {}
    done = 0
    if args.workers <= 1:
        for job in jobs:
            fp, feat = feature_job(job)
            cache[fp] = feat
            done += 1
            if done % 1000 == 0:
                logging.info("  features %d/%d", done, len(jobs))
    else:
        with Pool(args.workers) as pool:
            for fp, feat in pool.imap_unordered(feature_job, jobs, chunksize=64):
                cache[fp] = feat
                done += 1
                if done % 1000 == 0:
                    logging.info("  features %d/%d", done, len(jobs))
    valid = sum(1 for feat in cache.values() if feat)
    logging.info("feature cache ready: %d/%d non-empty", valid, len(cache))
    return cache


def save_tsv(rows, out_path, feature_cache):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["label", "text_a"])
        for label, flow_pcap in rows:
            feat = feature_cache.get(str(flow_pcap), "")
            if feat:
                writer.writerow([label, feat])
                written += 1
    logging.info("  -> %s (%d samples)", out_path, written)
    return written


def write_fold(samples_by_scenario, held, args, feature_cache):
    train, val, test = split_train_val(
        samples_by_scenario,
        held=held,
        val_ratio=args.val_ratio,
        seed=args.seed,
        valid_scenario=args.valid_scenario,
    )
    fold_dir = args.output_root / f"fold_{held[-1]}"
    logging.info(
        "fold_%s: train=%d val=%d test=%d",
        held[-1], len(train), len(val), len(test),
    )
    counts = {}
    for split, rows in (("train", train), ("val", val), ("test", test)):
        counts[split] = save_tsv(
            rows,
            fold_dir / f"{split}.tsv",
            feature_cache,
        )
    return counts


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flows-root", type=Path, default=DEFAULT_FLOWS_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--held", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--valid-scenario", choices=SCENARIOS, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    parser.add_argument("--max-flows", type=int, default=500)
    parser.add_argument("--first-n-pkts", type=int, default=5)
    parser.add_argument("--packet-bytes", type=int, default=640)
    parser.add_argument("--packet-bigrams", type=int, default=128)
    parser.add_argument("--min-pkt-len", type=int, default=40)
    parser.add_argument("--workers", type=int, default=12)
    return parser.parse_args()


def main():
    setup_logging()
    args = parse_args()
    args.flows_root = args.flows_root.resolve()
    args.output_root = args.output_root.resolve()
    logging.info("flows_root=%s", args.flows_root)
    logging.info("output_root=%s", args.output_root)

    classes = common_classes(args.flows_root)
    class_to_id = {cls: i for i, cls in enumerate(classes)}
    logging.info("%d common classes", len(classes))

    samples_by_scenario, scenario_counts = collect_scenario_samples(
        args.flows_root, classes, class_to_id, args.max_flows, args.seed
    )
    feature_cache = build_feature_cache(samples_by_scenario, args)

    held_scenarios = SCENARIOS if args.held == "all" else [args.held]
    fold_counts = {}
    for held in held_scenarios:
        fold_counts[held] = write_fold(samples_by_scenario, held, args, feature_cache)

    meta = {
        "dataset": "ITC-Net-Blend-60",
        "source_flows": str(args.flows_root),
        "trafficcogs_compatible": {
            "scenarios": SCENARIOS,
            "common_classes": True,
            "first_n_pkts": args.first_n_pkts,
            "packet_bytes": args.packet_bytes,
            "max_flows_per_scenario_class": args.max_flows,
            "flow_timeout_seconds": 120,
            "directional_flows": True,
        },
        "shortcut_removal": ["IPv4_SrcDst", "IPv6_SrcDst", "TCP_SrcDst", "UDP_SrcDst", "TLSCH_SNI"],
        "etbert": {
            "packet_bigrams": args.packet_bigrams,
            "format": "label/text_a TSV",
        },
        "classes": classes,
        "class_to_id": class_to_id,
        "scenario_sample_counts": scenario_counts,
        "fold_counts": fold_counts,
    }
    args.output_root.mkdir(parents=True, exist_ok=True)
    with (args.output_root / "meta.json").open("w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, ensure_ascii=False)
    logging.info("finished. meta=%s", args.output_root / "meta.json")


if __name__ == "__main__":
    main()
