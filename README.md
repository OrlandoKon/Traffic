# Debunking Representation Learning for Encrypted Traffic Classification

This repository contains the implementation of various baseline algorithms and data preprocessing methods.

## Folder Structure

- **code**: This folder contains the implementation of various baseline algorithms.
- **process_finetune_data**: This folder contains the methods for finetuned data preprocessing.

## Baseline Algorithms

The `code` folder includes the following baseline algorithms:
- Pcap Encoder
- [ET-BERT](https://github.com/linwhitehat/ET-BERT)
- [YaTC](https://github.com/NSSL-SJTU/YaTC)
- [NetMamba](https://github.com/wangtz19/NetMamba)
- [TrafficFormer](https://github.com/IDP-code/TrafficFormer)
- [netFound](https://github.com/SNL-UCSB/netFound)
- [AutoGluon](https://auto.gluon.ai/stable/index.html) based Feature Engineering

You can follow the installation instructions provided in the repositories to set up and test the environment. When reproducing results, we adhered to the official installation guides of each classifier and repository. If any conflicts arise between our instructions and the official guides, please prioritize the official documentation, as discrepancies are likely due to differences in environment configuration.

**Many thanks to authors for contributions.**

## Data Preprocessing

The `process_finetune_data` folder includes the following data preprocessing methods:
- **Split**: Per-packet/Per-flow split
- **Filter**: How to filter the irrelevant protocol packets
- **Data processing** (pkt/flow) of different models

Data is available on [HuggingFace](https://huggingface.co/datasets/rigcor7/Debunk_Traffic_Representation)
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all previous works.

## Reference
Please cite the paper published in ACM SIGCOMM 2025:

```
@inproceedings{zhaodebunking2025,
  author    = { Yuqi Zhao and
                Giovanni Dettori and
                Matteo Boffa and
                Luca Vassio and
                Marco Mellia},
  title     = {The Sweet Danger of Sugar: Debunking Representation Learning
               for Encrypted Traffic Classification},
  booktitle = {Proceedings of the ACM SIGCOMM 2025 Conference},
  pages     = {296--310},
  location  = {Coimbra, PT},
  series    = {ACM SIGCOMM '25}
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  year      = {2025}
}
```
