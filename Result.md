# Experiment Result
## ET-BERT
### ISCX-VPN-2016
|  K重交叉验证  | ACC.  |  Pre.  | Rec.  | F1. | Inference time | 
|  ----  | ----  | ----  | ----  | ---- | ---- |
| K0  | 0.2060 | 0.2101 | 0.2075 | 0.1278 | 0.0276
| K1  | 0.2060 | 0.1797  | 0.1659 | 0.1117 | 0.0275
| K2  | 0.2563 | 0.2653  | 0.1929 | 0.1452 | 0.0294
| Average | 0.2228 | 0.2184 | 0.1888 | 0.1282 | 0.0282 |

### TLS120
|  K重交叉验证  | ACC.  |  Pre.  | Rec.  | F1. | Inference time | 
|  ----  | ----  | ----  | ----  | ---- | ---- |
| K0  | 0.0888 | 0.0654 | 0.0803 | 0.0445 | 1.5463
| K1  | 0.0931 | 0.0618  | 0.0826 | 0.0465 | 1.5793
| K2  | 0.0911 | 0.0833  | 0.0823 | 0.0462 | 1.5485
| Average | 0.0910 | 0.0702 | 0.0817 | 0.0457 | 1.5580 |

### ITC-Net-Blend-60 OOD
| Fold | Held-out scenario | ACC. | Pre. | Rec. | F1. | Inference time |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| E | Scenario_E | 0.1871 | 0.2189 | 0.2044 | 0.1909 | 2.7636 |

Preprocess: TraffiCOGS-style 5-packet flow input, 53 common classes, IP addresses/ports/SNI removed. Split sizes: train 84314, val 9354, test 18130.
