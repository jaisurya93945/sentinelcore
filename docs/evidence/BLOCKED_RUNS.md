# Blocked runs — recorded, not substituted

Per the standing rule: when an experiment cannot be executed, record the attempt and the environment rather than fabricating or substituting a result.

## 1. Industry head-to-head vs Meta Llama Prompt Guard 2

| | |
|---|---|
| **Command** | `python scripts/benchmark_industry.py` |
| **Model** | `meta-llama/Llama-Prompt-Guard-2-86M` (mDeBERTa-base, 86M params) |
| **Dataset** | internal held-out split, n=149, `dataset/processed/splits.json`, seed 20260903 |
| **Threshold** | 0.5, max-score pooling over 512-token chunks |
| **Status** | **NOT RUN — blocked** |
| **Failure** | `huggingface.co` → HTTP 403, `x-deny-reason: host_not_allowed` |
| **Environment** | dev sandbox, Python 3.12, egress allowlist excludes huggingface.co and cdn-lfs.huggingface.co |
| **Note** | `transformers` and `torch` install fine from PyPI (allowed); the blocker is *weight download*, not the library |
| **Runnable by** | anyone with normal internet: `pip install -r requirements-industry.txt && python scripts/benchmark_industry.py` |

## 2. Over-defense vs NotInject

| | |
|---|---|
| **Command** | `python scripts/evaluate_overdefense.py --dataset notinject` |
| **Dataset** | NotInject (InjecGuard, arXiv:2410.22770), hosted on HuggingFace |
| **Status** | **NOT RUN — blocked** |
| **Failure** | same egress restriction; `datasets` library installs, dataset download does not |
| **Fallback executed** | `--dataset internal`, **n=5**, recorded in `dataset/processed/overdefense_results.json` |
| **Fallback validity** | **NONE for conclusions.** n=5. The script prints an explicit too-small warning. It exists to prove the pipeline runs |

## What is therefore unproven

- SentinelCore's detection performance **relative to any industry guardrail**. Every comparison to date is against our own weaker rules baseline.
- SentinelCore's **over-defense behaviour on hard benign inputs**. Finding 10 established that our corpus cannot measure this (5/399 benign examples carry attack vocabulary), and the external benchmark that can is unreachable from here.

Both are named in the paper's limitations. Neither has a substituted or estimated stand-in anywhere in this repository.
