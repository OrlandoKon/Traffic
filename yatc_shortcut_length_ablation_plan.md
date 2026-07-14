# 基于 YaTC 的“前 20 包是否足够”诊断消融实验方案

## 0. 实验目的

本实验只用于验证一个现象，不用于证明最终方法优劣：

> “前 20 个包就足够完成加密流量分类”这个结论，到底是因为前 20 包已经包含了真实应用行为信息，还是因为前 20 包里包含了强捷径信息？

这里的强捷径包括但不限于 IP、端口、TTL/Hop Limit、TCP window/options、SNI、ALPN、TLS cipher suites、TLS fingerprint、握手阶段固定模式、环境相关字段等。

核心判断逻辑：

```text
如果保留捷径时 first-20 已经接近饱和，
但去掉捷径后 first-20 明显下降，且更长片段 / 全流采样能恢复一部分性能，
则说明“前 20 包足够”很可能依赖早期强捷径。

如果去掉捷径后 first-20 仍然接近更长片段，
则说明在当前数据集上，应用可分类信息确实主要集中在流前段。

如果去掉捷径后所有设置都很差，
则不能说明长流没用，只能说明当前输入、模型或数据处理没有捕获到稳定应用信号。
```

---

## 1. 为什么用 YaTC

当前自研模型效果较差，不适合作为这个诊断实验的唯一模型。否则 `first-20` 和 `long-flow` 都差时，无法判断是“流长度无效”，还是“模型没有学到”。

因此本实验先使用 YaTC 作为相对强的 raw-byte backbone / diagnostic baseline。它的作用是：

1. 判断当前数据集里是否存在可被较强模型捕获的分类信号；
2. 比较不同包数预算下的性能变化；
3. 比较保留捷径和去除捷径后的性能变化；
4. 判断更长流片段是否在去捷径后提供额外信息。

注意：YaTC 只作为“探针模型”，不是最终方法。

---

## 2. 需要验证的核心问题

### Q1：保留捷径时，前 20 包是否已经饱和？

实验：

```text
YaTC + shortcut-rich input + first-K packets
K = 5, 10, 20, 50, 100
```

观察：

```text
Acc / Macro-F1 是否在 K=20 左右达到平台期。
```

### Q2：去掉强捷径后，前 20 包是否仍然足够？

实验：

```text
YaTC + shortcut-controlled input + first-K packets
K = 5, 10, 20, 50, 100
```

观察：

```text
去捷径后，K=20 到 K=50 / 100 是否仍有明显提升。
```

### Q3：流后段是否包含额外应用行为信息？

实验：

```text
YaTC + shortcut-controlled input + sample-K-from-whole-flow
K = 20, 50, 100
```

观察：

```text
在相同 K 下，whole-flow uniform sampling 是否优于 first-K。
```

如果 `sample-K-from-whole-flow > first-K`，说明流中后段存在额外信息。

### Q4：这个现象在 IID 和 OOD 划分下是否一致？

实验：

```text
IID split
Leave-One-Scenario-Out split
```

观察：

```text
IID 和 OOD 下的趋势是否一致。
OOD gap = IID Macro-F1 - OOD Macro-F1
```

如果原始输入 IID 好、OOD 差，说明捷径或环境偏移明显。

---

## 3. 实验变量

### 3.1 变量一：包数预算 K

建议先跑：

```text
K = 5, 10, 20, 50, 100
```

如果显存或训练时间不足，先跑最小集合：

```text
K = 10, 20, 50
```

### 3.2 变量二：包选择策略

#### A. prefix

取每条流的前 K 个包：

```text
first-K packets
```

用于验证“前 K 包是否足够”。

#### B. uniform_whole_flow

从整条流中均匀采样 K 个包：

```text
sample-K-from-whole-flow packets
```

示例：如果一条流有 N 个包，则取：

```python
idx = np.linspace(0, N - 1, K).round().astype(int)
```

如果 N < K，则补零或重复 padding，保持输入长度一致。

用于验证“流中后段是否有额外信息”。

### 3.3 变量三：捷径控制强度

建议分三档，先实现前两档。

#### shortcut_level = original

使用 YaTC 当前默认预处理或尽量接近原始输入。

目的：观察在 shortcut-rich setting 下，前 20 包是否已经足够。

#### shortcut_level = l3l4_mask

最小去捷径版本，建议优先实现。

需要 mask / zero 的字段：

```text
IP source address
IP destination address
TCP source port
TCP destination port
UDP source port
UDP destination port
```

如果实现方便，同时 mask：

```text
IPv4 TTL
IPv6 Hop Limit
IPv4 ToS / DSCP
IPv6 DSCP / ECN
TCP window
TCP options
TCP sequence number
TCP acknowledgment number
```

目的：先去掉最明显的网络、主机和传输层身份信息。

#### shortcut_level = tls_identity_mask

增强去捷径版本，优先级低于 `l3l4_mask`。

需要解析 TLS ClientHello，并 mask：

```text
SNI
ALPN
Cipher Suites
Supported Versions
Supported Groups
Signature Algorithms
PSK Key Exchange Modes
Session ID
Early Data / PSK identity if present
```

如果 TLS 解析成本太高，先不要阻塞实验。可以先用 `l3l4_mask` 跑主表，然后把 TLS identity mask 作为增强实验。

#### shortcut_level = handshake_drop_or_mask

最强控制版本，可选。

方式一：跳过前 H 个握手包后再取 K 个包：

```text
drop first H packets, then select K packets
H = 3, 5, 8
```

方式二：保留包位置，但将前 H 个包的 payload 或 TLS handshake bytes 置零。

这个版本的解释需要谨慎，因为它不仅去掉捷径，也可能去掉真实早期应用行为。

---

## 4. 推荐实验矩阵

### 4.1 最小可跑版本

先跑这个矩阵，确认实验管线和趋势。

| split | shortcut_level | packet_select | K |
|---|---|---|---|
| IID | original | prefix | 10, 20, 50 |
| IID | l3l4_mask | prefix | 10, 20, 50 |
| OOD / LOSO | original | prefix | 10, 20, 50 |
| OOD / LOSO | l3l4_mask | prefix | 10, 20, 50 |

最小版本回答两个问题：

```text
1. YaTC 在当前数据上能不能学起来？
2. 去掉 L3/L4 捷径后，K=20 是否还接近 K=50？
```

### 4.2 主实验版本

| split | shortcut_level | packet_select | K |
|---|---|---|---|
| IID | original | prefix | 5, 10, 20, 50, 100 |
| IID | l3l4_mask | prefix | 5, 10, 20, 50, 100 |
| OOD / LOSO | original | prefix | 5, 10, 20, 50, 100 |
| OOD / LOSO | l3l4_mask | prefix | 5, 10, 20, 50, 100 |
| OOD / LOSO | l3l4_mask | uniform_whole_flow | 20, 50, 100 |

### 4.3 增强实验版本

| split | shortcut_level | packet_select | K |
|---|---|---|---|
| OOD / LOSO | tls_identity_mask | prefix | 20, 50, 100 |
| OOD / LOSO | tls_identity_mask | uniform_whole_flow | 20, 50, 100 |
| OOD / LOSO | handshake_drop_or_mask | prefix | 20, 50, 100 |
| OOD / LOSO | handshake_drop_or_mask | uniform_whole_flow | 20, 50, 100 |

---

## 5. 数据划分

### 5.1 IID split

所有场景混合后随机划分 train / val / test。

建议比例：

```text
train : val : test = 7 : 1 : 2
```

注意：同一条原始流不能同时出现在 train 和 test。

### 5.2 OOD / Leave-One-Scenario-Out split

假设共有 5 个场景：

```text
Scenario_A
Scenario_B
Scenario_C
Scenario_D
Scenario_E
```

每次选择 1 个场景作为测试集，其余 4 个场景作为训练/验证集。

示例：

```text
Train: Scenario_B + Scenario_C + Scenario_D + Scenario_E
Test:  Scenario_A
```

5 个场景轮流作为 test，最后报告平均结果。

---

## 6. YaTC 需要改动的地方

Codex 需要先阅读 YaTC repo 的数据预处理和模型输入部分，找到以下逻辑：

```text
1. 从 pcap / flow 文件构造 YaTC 输入的位置
2. 每条 flow 选取多少个 packet 的位置
3. 每个 packet 截取多少 bytes 的位置
4. padding / truncation 的位置
5. 训练脚本读取 dataset / config 的位置
```

然后尽量做最小侵入式修改。

### 6.1 增加 packet_select 参数

新增参数：

```yaml
packet_select: prefix  # choices: [prefix, uniform_whole_flow]
packet_num: 20
```

逻辑：

```python
def select_packets(packets, packet_num, packet_select):
    n = len(packets)

    if packet_select == "prefix":
        selected = packets[:packet_num]

    elif packet_select == "uniform_whole_flow":
        if n == 0:
            selected = []
        elif n >= packet_num:
            idx = np.linspace(0, n - 1, packet_num).round().astype(int)
            selected = [packets[i] for i in idx]
        else:
            selected = packets[:]

    else:
        raise ValueError(f"Unknown packet_select: {packet_select}")

    # padding 到 packet_num
    selected = pad_packets(selected, packet_num)
    return selected
```

### 6.2 增加 shortcut_level 参数

新增参数：

```yaml
shortcut_level: original  # choices: [original, l3l4_mask, tls_identity_mask, handshake_drop_or_mask]
```

逻辑：

```python
def apply_shortcut_control(packet, shortcut_level):
    if shortcut_level == "original":
        return packet

    if shortcut_level == "l3l4_mask":
        packet = mask_ip_addresses(packet)
        packet = mask_ports(packet)
        packet = mask_env_host_fields_if_available(packet)
        return packet

    if shortcut_level == "tls_identity_mask":
        packet = mask_ip_addresses(packet)
        packet = mask_ports(packet)
        packet = mask_tls_clienthello_identity_fields(packet)
        return packet

    if shortcut_level == "handshake_drop_or_mask":
        # 这个通常不在单包函数里做，而是在 flow-level packet selection 前后做
        return packet

    raise ValueError(f"Unknown shortcut_level: {shortcut_level}")
```

### 6.3 保留方向信息

如果原 YaTC 使用方向信息，不要随便删除。方向序列本身可能是应用行为的一部分。

建议保留：

```text
packet direction
packet length after masking
relative order
```

### 6.4 控制变量

除了下面变量外，其他训练设置尽量固定：

```text
packet_num
packet_select
shortcut_level
split
random_seed
```

不要同时改模型深度、学习率、batch size、优化器、预训练策略，否则无法解释消融结果。

---

## 7. 配置文件建议

建议新增一个统一实验配置，例如：

```yaml
experiment_name: yatc_len_shortcut_ablation

model:
  backbone: yatc

input:
  packet_num: 20
  packet_select: prefix
  shortcut_level: l3l4_mask
  packet_bytes: default
  keep_direction: true

split:
  mode: loso
  test_scenario: Scenario_A
  val_ratio: 0.1

train:
  seed: 42
  batch_size: 64
  epochs: 50
  lr: 0.0001
  early_stop_patience: 10

metrics:
  - accuracy
  - macro_f1
  - per_class_f1
  - confusion_matrix
```

---

## 8. 批量运行脚本建议

建议写一个批量脚本生成所有配置并运行。

### 8.1 最小版本命令

```bash
python tools/run_yatc_ablation.py \
  --splits iid loso \
  --shortcut-levels original l3l4_mask \
  --packet-selects prefix \
  --packet-nums 10 20 50 \
  --seeds 42 43 44
```

### 8.2 主实验命令

```bash
python tools/run_yatc_ablation.py \
  --splits iid loso \
  --shortcut-levels original l3l4_mask \
  --packet-selects prefix uniform_whole_flow \
  --packet-nums 5 10 20 50 100 \
  --seeds 42 43 44
```

注意：`uniform_whole_flow` 可以只跑 `K = 20, 50, 100`，不用跑 5 和 10。

---

## 9. 输出文件要求

每次实验保存一个目录，目录名包含关键变量：

```text
outputs/
  yatc_len_ablation/
    split=loso_test=Scenario_A_shortcut=l3l4_mask_select=prefix_K=20_seed=42/
      config.yaml
      metrics.json
      confusion_matrix.csv
      per_class_f1.csv
      train_log.csv
      best_model.pt
```

### 9.1 metrics.json

至少包含：

```json
{
  "accuracy": 0.0,
  "macro_f1": 0.0,
  "weighted_f1": 0.0,
  "loss": 0.0,
  "best_epoch": 0,
  "num_train": 0,
  "num_val": 0,
  "num_test": 0
}
```

### 9.2 汇总结果 CSV

最终生成：

```text
results/yatc_length_shortcut_summary.csv
```

列名：

```text
run_id
split
train_scenarios
test_scenario
shortcut_level
packet_select
packet_num
seed
accuracy
macro_f1
weighted_f1
best_epoch
num_train
num_val
num_test
```

### 9.3 聚合结果 CSV

最终生成：

```text
results/yatc_length_shortcut_summary_agg.csv
```

按下面字段聚合：

```text
split
test_scenario
shortcut_level
packet_select
packet_num
```

统计：

```text
accuracy_mean
accuracy_std
macro_f1_mean
macro_f1_std
weighted_f1_mean
weighted_f1_std
```

---

## 10. 需要画的图

### 10.1 包数 K 曲线

图 1：IID 设置下不同 K 的性能

```text
x-axis: packet_num K
 y-axis: Macro-F1
 curve 1: original + prefix
 curve 2: l3l4_mask + prefix
```

图 2：OOD / LOSO 设置下不同 K 的性能

```text
x-axis: packet_num K
 y-axis: Macro-F1
 curve 1: original + prefix
 curve 2: l3l4_mask + prefix
```

图 3：去捷径后 prefix vs whole-flow sampling

```text
x-axis: packet_num K
 y-axis: Macro-F1
 curve 1: l3l4_mask + prefix
 curve 2: l3l4_mask + uniform_whole_flow
```

### 10.2 捷径下降量

计算：

```text
Shortcut Drop(K) = F1(original, prefix, K) - F1(l3l4_mask, prefix, K)
```

图：

```text
x-axis: packet_num K
 y-axis: Shortcut Drop
```

如果 K=20 的 Shortcut Drop 很大，说明前 20 包里存在强捷径。

### 10.3 长流增益

计算：

```text
Length Gain(K) = F1(l3l4_mask, prefix, K) - F1(l3l4_mask, prefix, 20)
```

重点看：

```text
K = 50
K = 100
```

如果 Length Gain 明显大于 0，说明去捷径后更长前缀有额外信息。

### 10.4 全流采样增益

计算：

```text
Whole-flow Gain(K) = F1(l3l4_mask, uniform_whole_flow, K) - F1(l3l4_mask, prefix, K)
```

如果 Whole-flow Gain 明显大于 0，说明流后段包含额外信息。

### 10.5 OOD Gap

计算：

```text
OOD Gap(K) = F1(IID, K) - F1(LOSO, K)
```

如果 original 的 OOD Gap 大，而 l3l4_mask 后 OOD Gap 变小，说明原始输入更依赖环境捷径。

---

## 11. 结果解释规则

### 情况 A：保留捷径时 K=20 饱和，去捷径后 K=50/100 提升

解释：

```text
前 20 包足够的现象可能主要由早期强捷径支撑。
去掉捷径后，更长流片段提供了额外应用行为信息。
```

这是最符合当前猜想的结果。

### 情况 B：保留捷径和去捷径后 K=20 都饱和

解释：

```text
在当前数据集和 YaTC 输入下，应用可分类信息主要集中在流前段。
更长流片段没有明显额外贡献。
```

### 情况 C：去捷径后所有 K 都很差

解释：

```text
不能说明长流没用。
可能原因包括：
1. 去捷径过度，真实应用行为也被破坏；
2. YaTC raw-byte 输入不适合当前 mask 方式；
3. 数据标签或类别本身难以区分；
4. 训练配置不足；
5. 流后段信息需要 burst-level / time-series 表示，而不是 raw-byte packet 表示。
```

### 情况 D：uniform_whole_flow 明显优于 prefix

解释：

```text
流中后段存在额外应用行为信息。
只取前 K 包会丢失一部分分类信号。
```

### 情况 E：original OOD 很差，l3l4_mask OOD 更稳但 IID 下降

解释：

```text
原始输入含有对 IID 有帮助但跨场景不稳定的捷径信息。
去捷径会降低 IID 表现，但可能改善 OOD 稳定性。
```

---

## 12. 优先级安排

### Stage 1：确认 YaTC 能否在当前数据上学起来

只跑：

```text
IID + original + prefix + K=20
LOSO + original + prefix + K=20
```

如果 IID 都很差，先检查数据和训练管线，不继续消融。

### Stage 2：最小消融

跑：

```text
split = IID, LOSO
shortcut_level = original, l3l4_mask
packet_select = prefix
K = 10, 20, 50
seed = 42, 43, 44
```

目的：先看是否有 shortcut drop 和 length gain。

### Stage 3：完整 K 曲线

跑：

```text
K = 5, 10, 20, 50, 100
```

目的：观察性能是否在 K=20 饱和。

### Stage 4：whole-flow sampling

跑：

```text
packet_select = uniform_whole_flow
K = 20, 50, 100
shortcut_level = l3l4_mask
split = LOSO
```

目的：判断流后段是否有额外信息。

### Stage 5：TLS identity mask / handshake mask

仅在前面实验跑通后再做。

---

## 13. 给 Codex 的具体任务清单

请 Codex 按以下顺序执行。

### Task 1：阅读项目结构

找出：

```text
1. 数据预处理入口
2. flow -> packet list 的位置
3. packet list -> YaTC tensor 的位置
4. 训练入口
5. 配置系统
6. metrics 计算位置
```

输出一个简短说明：

```text
docs/yatc_code_structure.md
```

### Task 2：实现 packet_select 和 packet_num

新增配置：

```yaml
packet_num: 20
packet_select: prefix
```

支持：

```text
prefix
uniform_whole_flow
```

保证所有输入 tensor shape 和原模型兼容。

### Task 3：实现 shortcut_level = original / l3l4_mask

新增配置：

```yaml
shortcut_level: original
```

至少支持：

```text
original
l3l4_mask
```

`l3l4_mask` 至少 mask：

```text
IP src/dst
TCP/UDP src/dst port
```

如果当前输入已经去掉某些字段，需要在日志中记录：

```text
字段是否原本已被 YaTC 默认处理
本次 mask 实际作用了哪些字段
```

### Task 4：实现 LOSO split

新增配置：

```yaml
split:
  mode: loso
  test_scenario: Scenario_A
```

要求：

```text
train: 其他场景
val: 从 train 场景中划分
 test: 指定 test_scenario
```

### Task 5：实现实验批处理脚本

新增脚本：

```text
tools/run_yatc_ablation.py
```

支持参数：

```text
--splits
--test-scenarios
--shortcut-levels
--packet-selects
--packet-nums
--seeds
```

### Task 6：实现结果汇总脚本

新增脚本：

```text
tools/collect_yatc_ablation_results.py
```

输出：

```text
results/yatc_length_shortcut_summary.csv
results/yatc_length_shortcut_summary_agg.csv
```

### Task 7：实现画图脚本

新增脚本：

```text
tools/plot_yatc_ablation.py
```

输出：

```text
figures/yatc_k_curve_iid.png
figures/yatc_k_curve_loso.png
figures/yatc_prefix_vs_wholeflow.png
figures/yatc_shortcut_drop.png
figures/yatc_length_gain.png
figures/yatc_ood_gap.png
```

---

## 14. 验收标准

### 14.1 代码层面

1. 所有新增参数能从配置文件和命令行读取；
2. 不同 `packet_num` 下模型输入 shape 正确；
3. `prefix` 和 `uniform_whole_flow` 的 packet index 选择可打印检查；
4. `l3l4_mask` 实际生效，并能保存若干 before/after 样例；
5. IID 和 LOSO split 不发生数据泄漏；
6. 每个 run 都保存 config、metrics 和日志；
7. 汇总 CSV 可以直接用于画图。

### 14.2 实验层面

至少得到以下结果：

```text
1. IID + original + prefix + K=10/20/50
2. IID + l3l4_mask + prefix + K=10/20/50
3. LOSO + original + prefix + K=10/20/50
4. LOSO + l3l4_mask + prefix + K=10/20/50
```

如果这部分趋势清晰，再继续跑完整实验。

---

## 15. 最终需要看的结论表

最终只需要先回答下面几个问题：

| 问题 | 看哪个指标 |
|---|---|
| YaTC 在当前数据上是否能学起来？ | IID original K=20 Macro-F1 |
| 前 20 包是否饱和？ | original prefix K=20 vs K=50/100 |
| 前 20 包是否依赖捷径？ | Shortcut Drop at K=20 |
| 去捷径后长流是否有帮助？ | Length Gain at K=50/100 |
| 流后段是否有额外信息？ | Whole-flow Gain at K=20/50/100 |
| 原始输入是否 OOD 不稳？ | OOD Gap |

---

## 16. 推荐先跑的最小命令

在实现完成后，先运行：

```bash
python tools/run_yatc_ablation.py \
  --splits iid loso \
  --shortcut-levels original l3l4_mask \
  --packet-selects prefix \
  --packet-nums 10 20 50 \
  --seeds 42 43 44

python tools/collect_yatc_ablation_results.py \
  --input-dir outputs/yatc_len_ablation \
  --output-dir results

python tools/plot_yatc_ablation.py \
  --summary results/yatc_length_shortcut_summary_agg.csv \
  --output-dir figures
```

---

## 17. 注意事项

1. 不要一开始就做复杂 TLS 解析，先完成 `original` 和 `l3l4_mask`。
2. 不要同时改模型结构和训练策略。
3. 不要只看 Accuracy，必须看 Macro-F1。
4. 类别不平衡时，Macro-F1 比 Accuracy 更关键。
5. 所有实验至少跑 3 个 seed。
6. LOSO 每个场景都要轮流作为 test，最后取平均。
7. 如果 IID original K=20 都很差，优先排查数据管线，而不是继续做消融。
8. 如果去捷径后性能全部崩掉，需要检查 mask 是否破坏了 packet length、direction、record length 等真实应用行为信息。
