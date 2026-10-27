# PhishShield URL Threat Model Evaluation Report

**Model Version:** `v1.0.0-20261010-hgb`  
**Evaluation Date:** `2026-10-10T05:49:46.318810+00:00`  
**Split Strategy:** Domain-Grouped Split (`GroupShuffleSplit` on `registrable_domain`) to strictly avoid domain leakage.

---

## 1. Held-Out Test Set Performance

The held-out test set contains **765 URLs** across **539 distinct registrable domains** (494 legitimate, 271 phishing).

| Metric | Threshold 0.50 | Suspicious Threshold (0.200) | Malicious Threshold (0.700) |
| :--- | :--- | :--- | :--- |
| **ROC-AUC** | **0.9994** | — | — |
| **PR-AUC** | **0.9990** | — | — |
| **Precision** | 0.9963 | 0.9963 | **1.0000** |
| **Recall** | 0.9815 | **0.9889** | 0.9631 |
| **F1 Score** | 0.9888 | 0.9926 | 0.9812 |
| **False Positive Rate** | 0.0020 | — | — |

### Confusion Matrix (at threshold = 0.50)
- **True Negatives (TN):** 493
- **False Positives (FP):** 1
- **False Negatives (FN):** 5
- **True Positives (TP):** 266

---

## 2. Real-World Sanity Set Performance

A curated sanity set of **117 URLs** (62 legitimate domains including bank/login portals, 55 recent phishing URLs) was evaluated separately:

- **ROC-AUC:** 0.9912
- **Precision:** 0.8983
- **Recall:** 0.9636
- **F1 Score:** 0.9298
- **False Positive Rate on Popular Legitimate Domains:** **9.68%**
- **Confusion Matrix:** TN=56, FP=6, FN=2, TP=53

---

## 3. Path-Balanced Ablation

Dataset bias commonly causes models to correlate the presence of deep URL paths with phishing. We analyzed performance split by path structure:

- **urls_with_deep_path** (642 samples): F1=0.9883, Precision=1.0000, Recall=0.9770
- **root_urls_only** (123 samples): F1=0.9908, Precision=0.9818, Recall=1.0000

---

## 4. Performance by Dataset Source

| Source | Count | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- |
| `curated_attack_patterns` | 1 | 0.0000 | 0.0000 | 0.0000 |
| `curated_hard_negative` | 60 | 0.0000 | 0.0000 | 0.0000 |
| `curated_official_homepage` | 15 | 0.0000 | 0.0000 | 0.0000 |
| `openphish` | 94 | 1.0000 | 0.9787 | 0.9892 |
| `tranco_top_sites` | 419 | 0.0000 | 0.0000 | 0.0000 |
| `urlhaus` | 176 | 1.0000 | 0.9886 | 0.9943 |

---

## 5. False Positive & False Negative Analysis

### False Positive Examples
- `https://ilfattoquotidiano.it/` (Score: 0.619, Source: tranco_top_sites)

### False Negative Examples
- `https://tinyurl.com/5xt56hx7` (Score: 0.152, Source: openphish)
- `https://zeradilcar.agency/support/s` (Score: 0.073, Source: openphish)
- `https://ikovrsps.com/Mina.jar` (Score: 0.229, Source: urlhaus)
- `https://ikovrsps.com/Ikov.jar` (Score: 0.212, Source: urlhaus)
- `https://paytm-cashback-reward.top/claim` (Score: 0.059, Source: curated_attack_patterns)

---

## 6. Honest Model Limitations

1. **Static URL-Only Input:** The model assesses lexical and structural URL patterns without accessing server content or executing JavaScript. Highly stealthy phishing sites using clean, newly registered custom domains without brand tokens may score lower.
2. **Domain Grouping Impact:** Evaluating with domain-grouped splits tests true generalisation to unseen domains. The metrics reported here reflect out-of-domain performance, avoiding artificially inflated random-split numbers.
3. **Defense-in-Depth:** In the live application, the ML score is never used in isolation; it works in tandem with deterministic brand-impersonation rules and reputation intelligence.
