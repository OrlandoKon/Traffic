# ISCX-VPN-2016 + ET-BERT 数据处理与训练设计方案

## 1. 目标

在 ISCX-VPN-2016 应用分类任务上，基于 ET-BERT 验证 4 种字段掩码策略（Group 0/1/2/3），评估"仅可用特征"与"全特征"在分类性能上的差异。完整实验描述见 [Experiment.md](../code/ET-BERT/Experiment.md)。

## 2. 文件清单

| 文件 | 角色 |
|---|---|
| `process_finetune_data/Data Processing/ET-BERT/gen_iscx_vpn_notebook.py` | 生成器脚本（运行后产出下方 notebook） |
| `process_finetune_data/Data Processing/ET-BERT/iscx_vpn_experiment_preprocess.ipynb` | 实际执行的数据处理 notebook（生成的，**不要手改**） |
| `code/ET-BERT/fine-tuning/run_classifier_ori.py` | ET-BERT 微调入口（已加 per-class 指标 + 混淆矩阵输出） |
| `code/ET-BERT/datasets/ISCX-VPN-2016/group_{0-3}/split_{0-2}/{train,val,test}.tsv` | 产出的训练数据 |
| `code/ET-BERT/logs/group_{0-3}.md` | 实验结果记录 |

## 3. 数据流水线

```
原始 pcap (按 app 分子目录)
    │
    ├─[Cell 4] 过滤 + 流提取
    │       is_unwanted() → 丢弃 ARP/ICMP/IGMP/DNS/DHCP/STUN/NBNS/LLMNR/NTP
    │       flow_key()    → 5-tuple，双向规范化（可改为单向，见 §4.4）
    │       TCP 状态机     → SYN 起会话、RST 结束（可改为单纯 5-tuple，见 §4.3）
    │       UDP 60s 超时切流
    │
    ├─[Cell 5-11] 包级掩码
    │       packet_to_feature(raw, group)
    │         Group 0：剥 Ether + IP 头（IHL）+ 4B 端口，全 payload 保留
    │         Group 1：保留 IP 头结构，字段级掩码到"仅可用特征"
    │         Group 2：Group 1 基础上额外保留 Seq/Ack/Options/部分 TLS 扩展
    │         Group 3：仅置零"捷径字段"（IP/port/window/SNI/Cipher）
    │       字节序列 → hex bigram（2 hex 字符 = 1 字节，stride=1 sliding window）
    │
    ├─[Cell 11] load_all_flows
    │       聚合每类的所有流，每流截前 FIRST_N_PKTS=5 包
    │       过滤：len(pkts) < 3 的流丢弃（对齐 ET-BERT get_feature_flow）
    │       cap：每类最多 MAX_FLOWS_PER_CLASS = 2400 条流
    │
    ├─[Cell 12-13] split_flows
    │       每类按 TRAIN:VAL:TEST = 8:1:1 比例 stratified split
    │       3 个固定 seed（[42, 123, 456]）→ 3 个独立 split
    │
    └─[Cell 13-14] save_tsv
            对每个 (seed, group) 组合输出 train/val/test.tsv
            列：label \t text_a（text_a 是 bigram 序列，多个包之间用 [SEP] 隔开）
```

## 4. 关键设计决策

### 4.1 后台协议过滤（已对齐 ET-BERT）

ET-BERT 原始 `clean_pcap` 用 tshark display filter：
```
not arp and not dns and not stun and not dhcpv6 and not icmpv6
and not icmp and not dhcp and not llmnr and not nbns and not ntp
and not igmp and frame.len > 80
```

我们的 [is_unwanted()](../process_finetune_data/Data%20Processing/ET-BERT/gen_iscx_vpn_notebook.py) 实现了**前 11 条**（ARP/ICMP/IGMP/DNS/DHCP/STUN/NBNS/LLMNR/NTP）。

**已删除：`frame.len > 80`**。原因见 §6 实验日志 Run3。

### 4.2 流提取：DLT_RAW 处理

ISCX-VPN-2016 的 28 个 `vpn_*.pcap` 文件是 DLT_RAW（无 Ethernet 头），`bytes(pkt)` 直接从 IP 头开始。ET-BERT 原始代码不处理这种情况（Scapy `sessions()` 要求 `'Ether' in p`，DLT_RAW 包全部归到 "Other" 桶失效）。

我们的修复：在 `extract_flows_from_pcap` 里，当 `not pkt.haslayer(scapy.Ether)` 时**前置 14 字节假 Ethernet 头**（00...00 + EtherType 根据 IP 版本选 0x0800 或 0x86DD），然后正常处理。

### 4.3 TCP 会话切分（已对齐 ET-BERT）

- 一个 directional 5-tuple = 一条流
- **不做** SYN/RST 状态机切分
- **不做** UDP 60s 超时切分

实现：[extract_flows_from_pcap()](../process_finetune_data/Data%20Processing/ET-BERT/gen_iscx_vpn_notebook.py)，逻辑等价于 Scapy `PacketList.sessions()`。

历史：早期版本曾用 TCP 状态机 + UDP 超时切分，后改为单 5-tuple 以对齐 ET-BERT。

### 4.4 流方向：单向（已对齐 ET-BERT）

- `flow_key = (src_ip, src_port, dst_ip, dst_port, proto)`，**不做** canonicalization
- A→B 和 B→A 是两条独立的流，独立分类
- 与 Scapy `sessions()` 默认行为一致

效果：一个 TCP 连接产出 2 条流，训练样本量 ×2。客户端发的字节和服务端发的字节作为独立样本，模式更"干净"（不会被双向穿插打乱）。

### 4.5 cap = 每类最多 2400 条流

[main.py:30](../code/ET-BERT/data_process/main.py#L30) 写死 `samples = [2400]`，我们对齐。

`count_label_number()` 风格：类样本不足 2400 时用实际数量（不补齐）。我们的 `load_all_flows` + `rng.sample(flows, MAX_FLOWS_PER_CLASS)` 等价。

### 4.6 每流取前 5 个包，每包 ≥3

- `FIRST_N_PKTS = 5`：对齐 ET-BERT flow-level 配置
- `len(pkts) < 3` 丢弃：对齐 ET-BERT 原始 [get_feature_flow](../code/ET-BERT/data_process/dataset_generation.py#L169) 的最小包数过滤

### 4.7 token 化：sliding-window hex bigram

```python
hex_str = raw.hex()
tokens = [hex_str[i:i+2] for i in range(len(hex_str)-1)]  # stride=1, len=2
```

- 每个 token 是 2 个 hex 字符（== 1 字节）
- 相邻 token **重叠 1 hex 字符**（半字节）
- 总长度截到 `PAYLOAD_LEN = 128` bigram per packet ≈ **64 字节覆盖**
- 注意：128 bigram 不是 128 字节，因为 stride=1

### 4.8 数据划分

- **3 个固定 seed**：[42, 123, 456]
- **每类独立 stratified split** = 8:1:1
- 每个 seed 产出一组 train/val/test，跨 4 个 Group 共享同一组流划分（同 seed 下 Group 0/1/2/3 切的是**完全相同的流**，区别只是包级掩码不同）

### 4.9 包级掩码（Group 0/1/2/3）

完整规范见 [Experiment.md](../code/ET-BERT/Experiment.md) §3。实现在 [gen_iscx_vpn_notebook.py](../process_finetune_data/Data%20Processing/ET-BERT/gen_iscx_vpn_notebook.py) Cell 5-11：

- **Group 0**：`bytes(pkt)[ether_off + ihl + 4:]`，剥头后全 payload 保留
- **Group 1**：保留 IP 头结构，所有字段按"可用特征"白名单掩码。Payload 仅保留 TLS Record Header 的 Content Type + Length，**Application Data 置零**
- **Group 2**：Group 1 + 额外保留 Seq/Ack/Options/部分 TLS 扩展
- **Group 3**：仅置零 IP/port/window/SNI/Cipher 等"捷径字段"，其余原始字节保留

## 5. 训练命令

```bash
CUDA_VISIBLE_DEVICES=1 python3 fine-tuning/run_classifier_ori.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --vocab_path           models/encryptd_vocab.txt \
    --train_path           datasets/ISCX-VPN-2016/group_0/split_0 \
    --dev_path             datasets/ISCX-VPN-2016/group_0/split_0 \
    --test_path            datasets/ISCX-VPN-2016/group_0/split_0 \
    --output_model_path    outputs/ISCX-VPN-2016/group_0/split_0 \
    --dataset              ISCX-VPN-2016 \
    --epochs_num   10  \
    --batch_size   32  \
    --seq_length   512 \
    --learning_rate 6e-5 \
    --dropout      0.5 \
    --embedding word pos seg \
    --encoder transformer \
    --mask    fully_visible
```

关键超参（对齐论文 [Experiment.md](../code/ET-BERT/Experiment.md) §5）：
- `learning_rate=6e-5`（论文 flow-level 设置）
- `dropout=0.5`、`epochs_num=10`、`batch_size=32`、`seq_length=512`
- **不使用** `--frozen`（开启会冻结 BERT 主体，导致性能崩盘）

## 6. 实验迭代日志

各次配置对比（仅 Group 0 / split 0）：

| Run | 配置 | Train | Test | Acc | F1 | 备注 |
|---|---|---|---|---|---|---|
| 1 | cap=500, 双向, session 切流, 无 DNS 过滤 | 4655 | 569 | 0.533 | **0.451** | facebook/hangout/skype 全混作 wpad |
| 2 | cap=2400, ET-BERT 等价切流 | 12881 | 1599 | 0.533 | 0.451 | 数据量翻倍但被 wpad 污染 |
| 3 | + DNS/control 过滤 + frame.len > 80 | 7364 | 909 | 0.536 | 0.328 | 80B 阈值误伤 scp/netflix，6 类崩盘 |
| 4 | + DNS 过滤，**去掉** 80B 阈值 | ~11k | 1385 | **0.739** | **0.585** | 当前基线 |

详细每类 F1 见 [code/ET-BERT/logs/group_0.md](../code/ET-BERT/logs/group_0.md)。

距离论文 ET-BERT(flow) F1=0.7306 还差 **~0.15**，主要拖后腿：
- aim (F1=0.00, support=11)、gmail (F1=0.00, support=17)：小类样本不够
- icq (F1=0.15)、sftp (F1=0.39)、spotify (F1=0.36)：协议特征不独特

## 7. 待解决

1. **三个 split + 4 个 Group 全跑**：当前仅 Group 0、Group 1 / split 0 跑通，剩 10 个组合待跑
2. **小类增强**（可选）：class weight 或 oversample，让 aim/gmail/icq 不被模型放弃
