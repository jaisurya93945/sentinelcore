# Dataset

Real, externally-sourced, labeled data used for evaluation (`scripts/evaluate.py`). See `docs/research/README.md` for the actual results.

## Sources & attribution

| File(s) | Source | License | Notes |
|---|---|---|---|
| `raw/deepset_train.parquet`, `raw/deepset_test.parquet` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), mirrored via [sinanw/llm-security-prompt-injection](https://github.com/sinanw/llm-security-prompt-injection) | MIT (mirror repo) | 662 examples, binary labeled (benign/injection), mostly English + some German |
| `raw/pr1m8_prompt_injections.csv` | [pr1m8/prompt-injections](https://github.com/pr1m8/prompt-injections) | MIT | 82 examples, categorized across 9 attack types, multiple languages |

Kaggle was the originally planned source (per the project design doc). Kaggle's API requires authenticated credentials this environment doesn't have, so these two GitHub-hosted, equivalently real and MIT-licensed datasets were used instead. A real Kaggle dataset with the same shape (labeled injection + benign, JSONL) also exists at `kaggle.com/datasets/cyberprince/prompt-injection-and-benign-prompt-dataset` if anyone wants to add it as a third source later.

## Structure

- `raw/` -- untouched downloads, exactly as fetched
- `processed/eval_set.jsonl` -- both sources normalized into one schema by `scripts/build_eval_dataset.py`:
  ```json
  {"id": "...", "text": "...", "label": "malicious|benign", "category": "...", "source": "...", "language": "...", "metadata": {}}
  ```
- `processed/eval_results.json` -- full output of `scripts/evaluate.py`, including every false negative/positive (the docs only show a 15-example preview)

## Regenerating

```bash
pip install -r requirements.txt -r scripts/requirements.txt
python scripts/build_eval_dataset.py
python scripts/evaluate.py
```
