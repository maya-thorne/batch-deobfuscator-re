---
license: gpl-3.0
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
  - split: test
    path: data/test-*
  - split: dev
    path: data/dev-*
dataset_info:
  features:
  - name: nl
    dtype: string
  - name: code
    dtype: string
  splits:
  - name: train
    num_bytes: 177292
    num_examples: 901
  - name: test
    num_bytes: 24382
    num_examples: 113
  - name: dev
    num_bytes: 22451
    num_examples: 113
  download_size: 116983
  dataset_size: 224125
---
