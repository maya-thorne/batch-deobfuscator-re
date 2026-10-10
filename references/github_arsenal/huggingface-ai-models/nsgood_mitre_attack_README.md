---
dataset_info:
  features:
  - name: Command
    dtype: string
  - name: TechniqueID
    dtype: string
  - name: TechniqueName
    dtype: string
  - name: Tactic
    dtype: string
  - name: OS
    dtype: string
  - name: Scenario
    dtype: string
  - name: Notes
    dtype: string
  splits:
  - name: train
    num_bytes: 159736
    num_examples: 513
  download_size: 36499
  dataset_size: 159736
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
---
