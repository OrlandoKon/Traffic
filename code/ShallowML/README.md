# Feature Engineering

Note: this code is based on [AutoGluon Library](https://auto.gluon.ai/stable/index.html).

## Data Processing
There are three ways to process the data

**Packet-level**
- Feature Alignment: Feature Engineering with padding zero to unknown field
- Raw: Using Raw data directly, and every 4 as a field
- Add_info_port: Add ip and port info based on the feature alignment

**Flow-level**
- Flow: Concat the first five packets with adding interval time

## Model Training and Evaluation
- install: [AutoGluon](https://auto.gluon.ai/stable/install.html)
- autogluon.ipynb: Training and Evaluation
- check_model.ipynb: Get feature importance based on sklearn module

## Install
```
conda create -n shallowml python=3.10 jupyterlab
conda activate shallowml
pip install -U pip
pip install -U setuptools wheel
pip install autogluon
```
## Use
```
conda activate shallowml
jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root \
  --ServerApp.token='' --ServerApp.password=''
```
