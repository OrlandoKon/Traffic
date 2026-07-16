#!/usr/bin/env python
# encoding=utf-8
"""
ITC-Net-Blend-60 -> YaTC OoD preprocessing.

This follows the TrafficCOGS-style ITC setting used elsewhere in this repo:
  - five scenarios: Scenario_A ... Scenario_E
  - label space is the intersection of classes across all five scenarios
  - leave-one-scenario-out folds
  - directional flows with a 120s idle timeout
  - first 5 packets per flow
  - per-scenario/per-class max 500 flows

Shortcut removal is mandatory:
  - IPv4/IPv6 source and destination addresses are zeroed
  - TCP/UDP source and destination ports are zeroed
  - TLS ClientHello SNI extension TLV is zeroed

Output is a torchvision ImageFolder-compatible YaTC dataset:
  output_root/
      samples/Scenario_X/Class/*.png
      fold_E/train_val_split_0/{train,val}/Class/*.png
      fold_E/test/Class/*.png
      meta.json

If samples already exist, pass --folds-only to rebuild fold directories
without reading the raw pcaps again.
"""
import argparse
import json
import logging
import os
import random
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


SCENARIOS = ["Scenario_A", "Scenario_B", "Scenario_C", "Scenario_D", "Scenario_E"]
DEFAULT_INPUT_ROOT = Path("/root/autodl-tmp/dataset/ITC-Net-Blend-60")
DEFAULT_OUTPUT_ROOT = Path("/root/autodl-tmp/dataset/ITC-Net-Blend-60-yatc-masked")

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


@dataclass
class FlowSample:
    scenario: str
    class_name: str
    source: str
    flow_id: int
    image_bytes: bytes
    packet_count: int


class Reservoir:
    def __init__(self, limit, rng):
        self.limit = limit
        self.rng = rng
        self.seen = 0
        self.items = []

    def add(self, item):
        self.seen += 1
        if len(self.items) < self.limit:
            self.items.append(item)
            return
        idx = self.rng.randrange(self.seen)
        if idx < self.limit:
            self.items[idx] = item


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )


def u16(buf, off):
    return struct.unpack("!H", bytes(buf[off:off + 2]))[0]


def common_classes(input_root):
    sets = []
    for scenario in SCENARIOS:
        sdir = input_root / scenario
        if not sdir.exists():
            raise FileNotFoundError(f"Missing scenario directory: {sdir}")
        sets.append({p.name for p in sdir.iterdir() if p.is_dir()})
    return sorted(set.intersection(*sets))


def ipv6_transport(buf, off=0):
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


def zero_client_hello_sni(buf, start, end):
    pos = start
    if pos + 34 > end:
        return 0
    pos += 2 + 32  # legacy_version + random
    if pos >= end:
        return 0
    session_id_len = buf[pos]
    pos += 1 + session_id_len
    if pos + 2 > end:
        return 0
    cipher_suites_len = u16(buf, pos)
    pos += 2 + cipher_suites_len
    if pos >= end:
        return 0
    compression_methods_len = buf[pos]
    pos += 1 + compression_methods_len
    if pos + 2 > end:
        return 0
    extensions_len = u16(buf, pos)
    ext_pos = pos + 2
    ext_end = min(ext_pos + extensions_len, end)

    masked = 0
    while ext_pos + 4 <= ext_end:
        ext_type = u16(buf, ext_pos)
        ext_len = u16(buf, ext_pos + 2)
        ext_total = 4 + ext_len
        if ext_pos + ext_total > ext_end:
            break
        if ext_type == TLS_EXT_SNI:
            buf[ext_pos:ext_pos + ext_total] = b"\x00" * ext_total
            masked += 1
        ext_pos += ext_total
    return masked


def zero_tls_sni(buf, tls_start):
    pos = tls_start
    n = len(buf)
    masked = 0
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
                    masked += zero_client_hello_sni(buf, hs_start, hs_end)
                hp = hs_end

        if rec_len == 0:
            break
        pos = rec_end
    return masked


def transport_offsets(raw_ip):
    if not raw_ip:
        return len(raw_ip), len(raw_ip), 0
    buf = raw_ip
    version = buf[0] >> 4

    if version == 4 and len(buf) >= 20:
        ihl = max(20, (buf[0] & 0x0F) * 4)
        proto = buf[9]
        transport_off = ihl
    elif version == 6 and len(buf) >= 40:
        transport_off, proto = ipv6_transport(buf, 0)
    else:
        return len(buf), len(buf), 0

    payload_off = len(buf)
    if proto == 6 and transport_off + 20 <= len(buf):
        data_offset = max(20, (buf[transport_off + 12] >> 4) * 4)
        payload_off = min(transport_off + data_offset, len(buf))
    elif proto == 17 and transport_off + 8 <= len(buf):
        payload_off = min(transport_off + 8, len(buf))
    return transport_off, payload_off, proto


def mask_shortcuts_ip_packet(raw_ip, stats):
    """Return IP-layer bytes with IP addresses, ports, and TLS SNI removed."""
    if not raw_ip:
        return b""
    buf = bytearray(raw_ip)
    version = buf[0] >> 4

    if version == 4 and len(buf) >= 20:
        buf[12:16] = b"\x00" * 4
        buf[16:20] = b"\x00" * 4
        stats["ipv4_addr_masked"] += 1
    elif version == 6 and len(buf) >= 40:
        buf[8:24] = b"\x00" * 16
        buf[24:40] = b"\x00" * 16
        stats["ipv6_addr_masked"] += 1
    else:
        return b""

    transport_off, payload_off, proto = transport_offsets(buf)
    if proto == 6 and transport_off + 20 <= len(buf):
        buf[transport_off:transport_off + 4] = b"\x00" * 4
        stats["tcp_ports_masked"] += 1
        stats["tls_sni_masked"] += zero_tls_sni(buf, payload_off)
    elif proto == 17 and transport_off + 8 <= len(buf):
        buf[transport_off:transport_off + 4] = b"\x00" * 4
        stats["udp_ports_masked"] += 1

    return bytes(buf)


def split_header_payload(masked_ip):
    _, payload_off, _ = transport_offsets(masked_ip)
    if payload_off >= len(masked_ip):
        return masked_ip, b""
    return masked_ip[:payload_off], masked_ip[payload_off:]


def fixed_bytes(data, length):
    if len(data) >= length:
        return data[:length]
    return data + (b"\x00" * (length - len(data)))


def flow_to_yatc_image_bytes(masked_packets, first_n_pkts):
    rows = []
    for packet in masked_packets[:first_n_pkts]:
        header, payload = split_header_payload(packet)
        rows.append(fixed_bytes(header, 80))
        rows.append(fixed_bytes(payload, 240))
    while len(rows) < first_n_pkts * 2:
        rows.append(b"\x00" * 80)
        rows.append(b"\x00" * 240)
    out = b"".join(rows)
    if len(out) != 1600:
        raise ValueError(f"YaTC image byte length should be 1600, got {len(out)}")
    return out


def packet_flow_key(pkt):
    if IP in pkt:
        ip = pkt[IP]
        src, dst, proto = ip.src, ip.dst, ip.proto
        raw_ip = bytes(ip)
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst, proto = ip.src, ip.dst, ip.nh
        raw_ip = bytes(ip)
    else:
        return None

    sport, dport = 0, 0
    if TCP in pkt:
        proto = 6
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = 17
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    key = (src, dst, sport, dport, proto)
    return key, raw_ip


def finalize_flow(flow, scenario, class_name, source, flow_id, first_n_pkts, min_pkt_len):
    packets = [p for p in flow["packets"] if len(p) >= min_pkt_len]
    if not packets:
        return None
    image_bytes = flow_to_yatc_image_bytes(packets, first_n_pkts)
    return FlowSample(
        scenario=scenario,
        class_name=class_name,
        source=source,
        flow_id=flow_id,
        image_bytes=image_bytes,
        packet_count=len(packets),
    )


def read_pcap_flow_samples(pcap_path, scenario, class_name, args, stats):
    flows = {}
    samples = []
    flow_seq = 0
    source = str(pcap_path)

    try:
        reader = scapy.PcapReader(str(pcap_path))
    except Exception as exc:
        logging.warning("Failed opening %s: %s", pcap_path, exc)
        return samples

    with reader:
        for packet_idx, pkt in enumerate(reader):
            if args.max_packets_per_pcap is not None and packet_idx >= args.max_packets_per_pcap:
                break
            info = packet_flow_key(pkt)
            if info is None:
                continue
            key, raw_ip = info
            try:
                ts = float(pkt.time)
            except Exception:
                ts = 0.0

            flow = flows.get(key)
            if flow is not None and ts - flow["last"] > args.flow_timeout:
                sample = finalize_flow(flow, scenario, class_name, source, flow_seq, args.first_n_pkts, args.min_pkt_len)
                flow_seq += 1
                if sample is not None:
                    samples.append(sample)
                flow = None

            if flow is None:
                flow = {"last": ts, "packets": []}
                flows[key] = flow
            flow["last"] = ts

            if len(flow["packets"]) < args.first_n_pkts:
                masked = mask_shortcuts_ip_packet(raw_ip, stats)
                if masked:
                    flow["packets"].append(masked)

    for flow in flows.values():
        sample = finalize_flow(flow, scenario, class_name, source, flow_seq, args.first_n_pkts, args.min_pkt_len)
        flow_seq += 1
        if sample is not None:
            samples.append(sample)
    return samples


def collect_samples(args, classes):
    rng = random.Random(args.seed)
    reservoirs = {
        (scenario, cls): Reservoir(args.max_flows, rng)
        for scenario in SCENARIOS
        for cls in classes
    }
    stats = {
        "ipv4_addr_masked": 0,
        "ipv6_addr_masked": 0,
        "tcp_ports_masked": 0,
        "udp_ports_masked": 0,
        "tls_sni_masked": 0,
        "pcaps_read": 0,
        "flows_seen": 0,
    }

    for scenario in SCENARIOS:
        for cls in classes:
            pcap_files = sorted((args.input_root / scenario / cls).glob("*.pcap"))
            if args.max_pcaps_per_class is not None:
                pcap_files = pcap_files[:args.max_pcaps_per_class]
            for pcap_path in pcap_files:
                stats["pcaps_read"] += 1
                flow_samples = read_pcap_flow_samples(pcap_path, scenario, cls, args, stats)
                stats["flows_seen"] += len(flow_samples)
                reservoir = reservoirs[(scenario, cls)]
                for sample in flow_samples:
                    reservoir.add(sample)
            logging.info(
                "%s/%s: pcaps=%d sampled=%d seen=%d",
                scenario,
                cls,
                len(pcap_files),
                len(reservoirs[(scenario, cls)].items),
                reservoirs[(scenario, cls)].seen,
            )

    by_scenario = {scenario: [] for scenario in SCENARIOS}
    scenario_counts = {scenario: {} for scenario in SCENARIOS}
    for scenario in SCENARIOS:
        for cls in classes:
            items = reservoirs[(scenario, cls)].items
            by_scenario[scenario].extend(items)
            scenario_counts[scenario][cls] = len(items)
        by_scenario[scenario].sort(key=lambda s: (s.class_name, s.source, s.flow_id))
        logging.info("%s: %d sampled flows", scenario, len(by_scenario[scenario]))

    return by_scenario, scenario_counts, stats


def save_sample_images(samples_by_scenario, output_root):
    sample_paths = {}
    sample_root = output_root / "samples"
    for scenario, samples in samples_by_scenario.items():
        for idx, sample in enumerate(samples):
            class_dir = sample_root / scenario / sample.class_name
            class_dir.mkdir(parents=True, exist_ok=True)
            image_name = f"{scenario}_{idx:06d}.png"
            path = class_dir / image_name
            arr = np.frombuffer(sample.image_bytes, dtype=np.uint8).reshape(40, 40)
            Image.fromarray(arr).save(path)
            sample_paths[id(sample)] = path
    return sample_paths


def load_existing_samples(output_root):
    meta_path = output_root / "meta.json"
    sample_root = output_root / "samples"
    if not meta_path.exists():
        raise FileNotFoundError(f"Missing meta file for --folds-only: {meta_path}")
    if not sample_root.exists():
        raise FileNotFoundError(f"Missing samples directory for --folds-only: {sample_root}")

    with meta_path.open("r", encoding="utf-8") as handle:
        meta = json.load(handle)
    classes = meta.get("classes")
    if not classes:
        raise ValueError(f"No classes found in {meta_path}")

    samples_by_scenario = {scenario: [] for scenario in SCENARIOS}
    sample_paths = {}
    scenario_counts = {scenario: {} for scenario in SCENARIOS}

    for scenario in SCENARIOS:
        for class_name in classes:
            class_dir = sample_root / scenario / class_name
            paths = sorted(class_dir.glob("*.png"))
            scenario_counts[scenario][class_name] = len(paths)
            for idx, path in enumerate(paths):
                sample = FlowSample(
                    scenario=scenario,
                    class_name=class_name,
                    source=str(path),
                    flow_id=idx,
                    image_bytes=b"",
                    packet_count=0,
                )
                samples_by_scenario[scenario].append(sample)
                sample_paths[id(sample)] = path
        logging.info("%s: loaded %d existing samples", scenario, len(samples_by_scenario[scenario]))

    return meta, classes, samples_by_scenario, sample_paths, scenario_counts


def split_train_val(samples_by_scenario, held, val_ratio, seed):
    train_scenarios = [s for s in SCENARIOS if s != held]
    test = list(samples_by_scenario[held])
    by_class = {}
    for scenario in train_scenarios:
        for sample in samples_by_scenario[scenario]:
            by_class.setdefault(sample.class_name, []).append(sample)

    rng = random.Random(seed)
    train, val = [], []
    for cls in sorted(by_class):
        rows = list(by_class[cls])
        rng.shuffle(rows)
        n_val = max(1, int(len(rows) * val_ratio))
        val.extend(rows[:n_val])
        train.extend(rows[n_val:])
    rng.shuffle(train)
    rng.shuffle(val)
    return train, val, test


def link_or_copy(src, dst, copy_files):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    if copy_files:
        shutil.copy2(src, dst)
    else:
        rel_src = os.path.relpath(src, dst.parent)
        os.symlink(rel_src, dst)


def write_split(rows, split_dir, sample_paths, classes, copy_files):
    for cls in classes:
        (split_dir / cls).mkdir(parents=True, exist_ok=True)
    for idx, sample in enumerate(rows):
        src = sample_paths[id(sample)]
        dst = split_dir / sample.class_name / f"{idx:07d}_{src.name}"
        link_or_copy(src, dst, copy_files)
    return len(rows)


def write_folds(samples_by_scenario, sample_paths, classes, args):
    held_scenarios = SCENARIOS if args.held == "all" else [args.held]
    fold_counts = {}
    for held in held_scenarios:
        train, val, test = split_train_val(samples_by_scenario, held, args.val_ratio, args.seed)
        fold_dir = args.output_root / f"fold_{held[-1]}"
        if fold_dir.exists():
            shutil.rmtree(fold_dir)
        logging.info("fold_%s: train=%d val=%d test=%d", held[-1], len(train), len(val), len(test))
        fold_counts[held] = {
            "train": write_split(
                train,
                fold_dir / "train_val_split_0" / "train",
                sample_paths,
                classes,
                args.copy_files,
            ),
            "val": write_split(
                val,
                fold_dir / "train_val_split_0" / "val",
                sample_paths,
                classes,
                args.copy_files,
            ),
            "test": write_split(
                test,
                fold_dir / "test",
                sample_paths,
                classes,
                args.copy_files,
            ),
        }
    return fold_counts


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--held", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    parser.add_argument("--max-flows", type=int, default=500)
    parser.add_argument("--first-n-pkts", type=int, default=5)
    parser.add_argument("--flow-timeout", type=float, default=120.0)
    parser.add_argument("--min-pkt-len", type=int, default=40)
    parser.add_argument("--max-pcaps-per-class", type=int, default=None,
                        help="Debug option: only read the first N pcaps per scenario/class.")
    parser.add_argument("--max-packets-per-pcap", type=int, default=None,
                        help="Debug option: stop reading each pcap after N packets.")
    parser.add_argument("--max-classes", type=int, default=None,
                        help="Debug option: only process the first N common classes.")
    parser.add_argument("--copy-files", action="store_true",
                        help="Copy images into folds instead of symlinking sample images.")
    parser.add_argument("--folds-only", action="store_true",
                        help="Reuse output-root/samples and rebuild fold directories without reading pcaps.")
    parser.add_argument("--overwrite", action="store_true",
                        help="Delete output-root before writing.")
    return parser.parse_args()


def main():
    setup_logging()
    args = parse_args()
    args.input_root = args.input_root.resolve()
    args.output_root = args.output_root.resolve()

    if args.folds_only:
        logging.info("output_root=%s", args.output_root)
        meta, classes, samples_by_scenario, sample_paths, scenario_counts = load_existing_samples(args.output_root)
        fold_counts = write_folds(samples_by_scenario, sample_paths, classes, args)
        meta["scenario_sample_counts"] = scenario_counts
        meta["fold_counts"] = fold_counts
        meta["fold_storage"] = "copies" if args.copy_files else "symlinks"
        with (args.output_root / "meta.json").open("w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2, ensure_ascii=False)
        logging.info("finished folds-only rebuild. meta=%s", args.output_root / "meta.json")
        return

    if args.output_root.exists():
        if not args.overwrite:
            raise FileExistsError(f"{args.output_root} already exists; pass --overwrite to rebuild it")
        shutil.rmtree(args.output_root)
    args.output_root.mkdir(parents=True, exist_ok=True)

    logging.info("input_root=%s", args.input_root)
    logging.info("output_root=%s", args.output_root)
    classes = common_classes(args.input_root)
    if args.max_classes is not None:
        classes = classes[:args.max_classes]
    logging.info("%d common classes", len(classes))

    samples_by_scenario, scenario_counts, mask_stats = collect_samples(args, classes)
    sample_paths = save_sample_images(samples_by_scenario, args.output_root)
    fold_counts = write_folds(samples_by_scenario, sample_paths, classes, args)

    meta = {
        "dataset": "ITC-Net-Blend-60",
        "source": str(args.input_root),
        "format": "YaTC 40x40 PNG ImageFolder",
        "trafficcogs_compatible": {
            "scenarios": SCENARIOS,
            "common_classes": True,
            "directional_flows": True,
            "flow_timeout_seconds": args.flow_timeout,
            "first_n_pkts": args.first_n_pkts,
            "max_flows_per_scenario_class": args.max_flows,
            "val_ratio": args.val_ratio,
            "seed": args.seed,
        },
        "shortcut_removal": ["IPv4_SrcDst", "IPv6_SrcDst", "TCP_SrcDst", "UDP_SrcDst", "TLSCH_SNI"],
        "classes": classes,
        "class_to_id": {cls: idx for idx, cls in enumerate(classes)},
        "scenario_sample_counts": scenario_counts,
        "fold_counts": fold_counts,
        "mask_stats": mask_stats,
        "fold_storage": "copies" if args.copy_files else "symlinks",
    }
    with (args.output_root / "meta.json").open("w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, ensure_ascii=False)
    logging.info("finished. meta=%s", args.output_root / "meta.json")


if __name__ == "__main__":
    main()
