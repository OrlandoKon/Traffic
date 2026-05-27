# 验证实验方案：基于可用特征分类的 ET-BERT 加密流量分类实验

## 一、实验目标

在 ISCX-VPN-2016 数据集上，使用 ET-BERT 模型，对比"全特征"与"仅可用特征"的分类效果。通过对协议头各字段进行语义级别的掩码（置零），验证去除捷径特征和无关特征后，仅依赖可用特征进行分类能达到什么水平的性能。

## 二、协议字段语义分类表

以下是对 5 种主要协议（IPv4、IPv6、TCP、UDP、TLS）中各字段的语义分类，共分为 5 类：捷径、无关特征、捷径/无关特征、捷径/可用特征、可用特征。

| 分类 | IPv4 | IPv6 | UDP | TCP | Client Hello (TLS) | Server Hello (TLS) | Record Header (TLS) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 捷径 | Source/Dst Addresses | Source/Dst Addresses, Hop Limit | Source/Dst Ports | Source/Dst Ports, Window, Data Offset | Cipher Suites, SNI | Cipher Suites | — |
| 无关特征 | Checksum | Traffic Class (ECN) | Checksum | Urgent Pointer, Flags (URG/ACK), Checksum, Rsrvd | Legacy Version, Random, Legacy Session ID, Legacy Compression Methods, Early Data | Legacy Version, Random, Legacy Session ID Echo, Legacy Compression Methods, Key Share | Legacy Version |
| 捷径/无关特征 | Identification, Flags (MF), Version, TTL, Fragment Offset | Flow Label, Version, Traffic Class (DSCP) | — | Sequence Numbers, Acknowledgment Numbers, Options, Flags (CWR/ECE) | PRE Shared Key | Supported Versions, PRE Shared Key | — |
| 捷径/可用特征 | — | — | — | — | Supported Versions, Supported Groups, Supported Algorithms, PSK Key Exchange | — | — |
| 可用特征 | IHL, Type of Service, Flags (DF), Total Length, Protocol | Payload Length, Next Header | Length | Flags (RST/SYN/FIN/PSH) | ALPN | — | Content Type, Length |

## 三、实验分组

### Group 0 — Baseline（复现 ET-BERT 论文原始设置）

严格按照 ET-BERT 论文 Section 4.1.2 的预处理方式：

**去除的部分：**
- 去除 Ethernet header（14 字节）
- 去除整个 IP header（IPv4 为 20 字节，IPv6 为 40 字节）
- 去除 TCP/UDP 的 Source Port 和 Destination Port（各 2 字节，共 4 字节）
- 去除 ARP 和 DHCP 数据包

**保留的部分：**
- TCP header 的端口之后的全部字段（Sequence Number、Acknowledgment Number、Data Offset、Flags、Window、Checksum、Urgent Pointer、Options）
- 或 UDP header 的端口之后的全部字段（Length、Checksum）
- 全部 payload（包括 TLS 握手和加密数据）

**不做任何字段级掩码**，保留上述所有字节的原始值。

目标：复现出接近论文报告的数值
---

### Group 1 — 仅可用特征

**不去掉 IP 头**，保留从 IP 头开始的完整协议栈字节结构，但对所有协议层做字段级掩码。仅保留"可用特征"列中的字段值，其余所有字段全部置零（0x00）。

具体掩码方案：

**IPv4 头（20 字节，不含 Options）：**
- 保留：IHL（第 0 字节低 4 位）、Type of Service（第 1 字节）、Total Length（第 2-3 字节）、Flags 中的 DF 位（第 6 字节 bit 6）、Protocol（第 9 字节）
- 置零：Version（第 0 字节高 4 位）、Identification（第 4-5 字节）、Flags 中的 MF 位、Fragment Offset（第 6-7 字节剩余位）、TTL（第 8 字节）、Header Checksum（第 10-11 字节）、Source IP（第 12-15 字节）、Destination IP（第 16-19 字节）

**IPv6 头（40 字节）：**
- 保留：Payload Length（第 4-5 字节）、Next Header（第 6 字节）
- 置零：Version（第 0 字节高 4 位）、Traffic Class（第 0-1 字节中间 8 位）、Flow Label（第 1-3 字节低 20 位）、Hop Limit（第 7 字节）、Source Address（第 8-23 字节）、Destination Address（第 24-39 字节）

**TCP 头（20 字节，不含 Options）：**
- 保留：Flags 中的 RST/SYN/FIN/PSH 四个标志位（第 13 字节中的对应位）
- 置零：Source Port（第 0-1 字节）、Destination Port（第 2-3 字节）、Sequence Number（第 4-7 字节）、Acknowledgment Number（第 8-11 字节）、Data Offset（第 12 字节高 4 位）、Reserved（第 12 字节低 4 位）、Flags 中的 CWR/ECE/URG/ACK 位（第 13 字节中的对应位）、Window（第 14-15 字节）、Checksum（第 16-17 字节）、Urgent Pointer（第 18-19 字节）
- TCP Options（如存在）：全部置零

**UDP 头（8 字节）：**
- 保留：Length（第 4-5 字节）
- 置零：Source Port（第 0-1 字节）、Destination Port（第 2-3 字节）、Checksum（第 6-7 字节）

**TLS Client Hello（在 payload 中）：**
- 保留：ALPN 扩展（Extension Type = 0x0010）的完整 TLV 结构
- 保留：TLS Record Header 中的 Content Type（1 字节）和 Length（2 字节）
- 置零：SNI 扩展（Extension Type = 0x0000）、Cipher Suites 列表、Legacy Version、Random（32 字节）、Legacy Session ID、Legacy Compression Methods、Early Data 扩展、以及其他未被标记为"可用"的扩展字段

**TLS Server Hello（在 payload 中）：**
- 保留：TLS Record Header 中的 Content Type（1 字节）和 Length（2 字节）
- 置零：所有其他字段（Legacy Version、Random、Session ID Echo、Cipher Suite、Compression Method、所有扩展）

**TLS Record Header（Application Data 等）：**
- 保留：Content Type（1 字节）和 Length（2 字节）
- 置零：Legacy Version（2 字节）

**加密 payload（Application Data）：** 全部去除，只保留Payload的长度

---

### Group 2 — 可用特征 + 可能可用特征

在 Group 1 的基础上，额外保留以下"捷径/可用特征"和部分"捷径/无关特征"中的字段：

**TCP 头额外保留：**
- Sequence Number（第 4-7 字节）
- Acknowledgment Number（第 8-11 字节）
- Options（如存在）
- Flags 中的 CWR/ECE 位

**TLS Client Hello 额外保留：**
- Supported Versions 扩展（Extension Type = 0x002b）
- Supported Groups 扩展（Extension Type = 0x000a）
- Signature Algorithms 扩展（Extension Type = 0x000d）
- PSK Key Exchange Modes 扩展（Extension Type = 0x002d）

**TLS Server Hello 额外保留：**
- Supported Versions 扩展（Extension Type = 0x002b）
- PRE Shared Key 扩展（Extension Type = 0x0029）

其余掩码策略与 Group 1 一致。

---

### Group 3 — 去捷径特征

保留从 IP 头开始的完整协议栈字节结构，仅将"捷径"列的字段置零，其余所有字段（包括"无关特征"、"捷径/无关特征"、"可用特征"）全部保留原始值。

**置零的字段（仅"捷径"列）：**

| 协议层 | 置零的字段 |
| --- | --- |
| IPv4 | Source IP Address, Destination IP Address |
| IPv6 | Source Address, Destination Address, Hop Limit |
| TCP | Source Port, Destination Port, Window, Data Offset |
| UDP | Source Port, Destination Port |
| TLS Client Hello | SNI 扩展, Cipher Suites 列表 |
| TLS Server Hello | Cipher Suites |

**其余所有字段保留原始值**，包括 Checksum、Random、Session ID、Seq/Ack Number、Version、TTL 等"无关特征"和"捷径/无关特征"。

## 四、任务与数据集

**数据集：** ISCX-VPN-2016

**分类任务：**

- ISCX-VPN-App：17 类（按应用分类：AIM、Email、Facebook、FTPS、Gmail、Hangout、ICQ、Netflix、SCP、SFTP、Skype、Spotify、Tor、Torrent、Vimeo、Voipbuster、YouTube）

**输入格式：** First n Bytes per packet of First m packets（m=5，n 沿用 ET-BERT 论文设置，为1024字节）

**数据预处理：**
- 去除 ARP 和 DHCP 数据包
- 按五元组（Src IP, Dst IP, Src Port, Dst Port, Protocol）聚合为流
- Group 0 按论文方式剥离 Ethernet/IP/端口后截取字节
- Group 1/2/3 保留 IP 头，做字段级掩码后截取字节

**数据划分：**
- 按流划分（flow-based split）
- 训练集 : 验证集 : 测试集 = 8 : 1 : 1
- 每类最多 500 条流
- 固定 3 个随机种子，取均值 ± 标准差

## 五、模型与训练设置

沿用 ET-BERT 论文的模型配置和超参数：

- 模型架构：12 层 Transformer，12 个 attention heads，hidden size = 768，max token = 512
- 预训练模型：使用 ET-BERT 官方发布的预训练权重（https://github.com/linwhitehat/ET-BERT）
- 微调策略：仅使用 ET-BERT(flow)，即取每条流的前 m 个包，每包前 n 字节，拼接为输入
- 优化器：AdamW
- 学习率：6×10⁻⁵
- Batch size：32
- Dropout：0.5
- Epochs：10
- Warmup ratio：0.1

## 六、评估指标

- Macro Accuracy (AC)
- Macro Precision (PR)
- Macro Recall (RC)
- Macro F1

与 ET-BERT 论文使用的指标完全一致。

## 七、结果呈现

### 表 2：ISCX-VPN-App 分类结果（3 个随机种子的均值 ± 标准差）

|  | AC | PR | RC | F1 |
| --- | --- | --- | --- | --- |
| ET-BERT 论文值 (flow) | 0.8519 | 0.7508 | 0.7294 | 0.7306 |
| Group 0 — Baseline | 0.5343 ± 0.0025 | 0.5098 ± 0.0251 | 0.4827 ± 0.0151 | 0.4709 ± 0.0204 |
| Group 1 — 仅可用特征 | 0.2578 ± 0.0990 | 0.1390 ± 0.0943 | 0.2092 ± 0.0903 | 0.1508 ± 0.0953 |
| Group 2 — 可用+可能可用 | 0.2279 ± 0.0602 | 0.1070 ± 0.0716 | 0.1803 ± 0.0502 | 0.1142 ± 0.0590 |
| Group 3 — 去捷径 | 0.4019 ± 0.0896 | 0.2891 ± 0.1155 | 0.3391 ± 0.0825 | 0.2929 ± 0.0958 |

### 表 3：各 split 的详细结果

| Group | Split | AC | PR | RC | F1 |
| --- | --- | --- | --- | --- | --- |
| 0 | 0 | 0.5325 | 0.4811 | 0.4819 | 0.4584 |
| 0 | 1 | 0.5378 | 0.5422 | 0.5015 | 0.4996 |
| 0 | 2 | 0.5325 | 0.5061 | 0.4646 | 0.4546 |
| 1 | 0 | 0.3779 | 0.2470 | 0.3195 | 0.2620 |
| 1 | 1 | 0.1353 | 0.0173 | 0.0982 | 0.0293 |
| 1 | 2 | 0.2601 | 0.1526 | 0.2100 | 0.1610 |
| 2 | 0 | 0.1793 | 0.0338 | 0.1337 | 0.0532 |
| 2 | 1 | 0.1916 | 0.0830 | 0.1574 | 0.0953 |
| 2 | 2 | 0.3128 | 0.2043 | 0.2499 | 0.1940 |
| 3 | 0 | 0.4534 | 0.3230 | 0.3845 | 0.3411 |
| 3 | 1 | 0.4763 | 0.4106 | 0.4095 | 0.3785 |
| 3 | 2 | 0.2759 | 0.1338 | 0.2234 | 0.1590 |

### 结果分析

**1. Group 0 与论文存在显著差距（F1 0.47 vs 论文 0.73）**

- 三个 split 结果一致（F1 std=0.02），说明训练本身稳定，差距来自数据/预处理而非随机性。
- 主要怀疑点：
  - **类别不平衡严重**：aim/icq 在 train 中仅 53–57 条，test 中仅 6 条；ftp/scp/skype 等大类被 `MAX_FLOWS_PER_CLASS=500` 截断，整体规模偏小。
  - **流切分粒度差异**：论文使用 SplitCap 按 session 切分，本实验用 5-tuple + SYN/RST + UDP 60s 超时切分，结果略有不同。
  - **类别集合不完全匹配**：论文 17 类，本实验目录中只有 16 类（aim、email、facebook、ftp、gmail、hangout、icq、netflix、scp、sftp、skype、spotify、torrent、vimeo、voipbuster、youtube），缺少一个类别（可能是 vpn vs non-vpn 拆分或 hangouts/bittorrent 拼写差异）。

**2. Group 1/2/3 出现训练崩塌与高方差**

- Group 1 split_1 的 F1 仅 0.0293（16 类随机猜也有 1/16=0.0625），说明模型坍缩到了某个 majority class。
- Group 2 三个 split F1 在 0.05–0.19 之间，整体退化最严重。Group 2 在 Group 1 基础上额外保留 Seq/Ack/Options 等"捷径/可用特征"，理论上信息量更多，但反而比 Group 1 更差，**这是一个反常现象**，可能原因：
  - 多保留的字段引入了和 5 元组类似的捷径信号噪声，但又被部分掩码破坏了语义连续性
  - 训练 seed 触发的随机坍缩
- Group 3 最高的 split（F1=0.3785）反而比 Group 1 最高的 split（F1=0.2620）好，说明保留 checksum/random/seq 这些"无关/捷径无关"字段对模型有帮助——这与论文常见假设（无关字段应被去除）有出入。

**3. Group 2 < Group 1 < Group 3 的现象**

按"保留信息量"排序应为 Group 3 > Group 2 > Group 1，实验中 F1 排序为 Group 3 > Group 1 > Group 2，Group 2 反常。需进一步检查：
- Group 2 的 mask 实现是否正确（特别是 TLS 扩展级保留逻辑）
- 是否 Group 2 的字节模式更容易让模型陷入捷径学习陷阱

**4. 数据规模与方差**

- 共 16 类、训练集仅 ~4655 条样本，平均每类不足 300 条，少数类不足 60 条。
- 在 header-only 设定下（Group 1/2），少量样本难以支撑细粒度区分，方差极大（F1 std 0.06–0.10）。

### 待跟进项

1. 核对类别集合，确认是 16 还是 17 类，确认与论文一致
2. 取消 `MAX_FLOWS_PER_CLASS` 上限，看 Group 0 能否接近论文 0.73
3. 复核 Group 2 的掩码实现，找出 Group 2 < Group 1 的原因
4. Group 1/2 加入 class weight 或 label smoothing 缓解 majority-class 坍缩

## 八、注意事项

1. **截断策略差异：** Group 0 的输入不含 IP 头（已被剥离），Group 1/2/3 的输入包含 IP 头（虽然大部分被置零），因此在相同的 token 截断长度下，Group 1/2/3 中 payload 的覆盖量会少于 Group 0。这个差异本身也是实验结果的一部分。

2. **TLS 扩展解析：** TLS 握手中的扩展字段采用 TLV（Type-Length-Value）编码，长度可变。掩码实现需要逐个解析扩展类型（Extension Type），按类型判断是保留还是置零。建议使用 Scapy 的 TLS 模块进行解析。

3. **预训练权重复用：** 所有 Group 共享同一个 ET-BERT 预训练权重，仅在微调阶段使用不同的掩码数据。不重新进行预训练。

4. **Group 0 与论文差异：** 如果 Group 0 的复现结果与论文报告值存在差异（±2% 以内视为正常），后续分析以自己复现的 Group 0 为内部 Baseline，同时报告论文原始数值作为参考。