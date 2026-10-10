---
license: apache-2.0
---
# Cybersecurity Detection Rules Dataset

This dataset contains a collection of 950 detection rules from official SIGMA, YARA, and Suricata repositories. Knowledge distillation was applied to generate questions for each rule and enrich the responses, using 0dAI-7.5B.

## Contents
- A set of detection rules for cybersecurity threat and intrusion detection in JSONL format (rules_dataset.jsonl). It contains the prompts and the associated responses. 
- The rules have been obtained from SIGMA, YARA, and Suricata official repositories.


## Usage
This dataset can be used to fine-tune LLM models or create cybersecurity applications focused on threat and intrusion detection. It is ideal for researchers and practitioners in cybersecurity looking to leverage a curated corpus of detection rules.

You can adjust this dataset with the prompt template of the model you want to fine-tune, in a simple way, with the following code, assuming that you have divided it into two sets for training and testing: 

```python

from datasets import load_dataset

# LLaMA3 prompt template

def format_prompt(prompt, response):
  return f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\nYou are a helpful assistant.<|eot_id|>\n<|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|>\n<|start_header_id|>assistant<|end_header_id|>\n{response}<|eot_id|>\n"

# Dataset load
train_dataset = load_dataset("json", data_files="/path/to/train.json")
val_dataset = load_dataset("json", data_files="/path/to/val.json")

train_dataset["validation"] = val_dataset["train"]

# Map dataset with the prompt template

mapped_qa_dataset = train_dataset.map(lambda samples: tokenizer(format_prompt(samples['instruction'], samples['output'])))

# print some examples
print(mapped_qa_dataset['train'][0])
print(mapped_qa_dataset['train'][1])
```

## License
This dataset is shared under an apache-2.0 license. Please review the licensing terms in this repository to ensure compliance with any restrictions or requirements.
