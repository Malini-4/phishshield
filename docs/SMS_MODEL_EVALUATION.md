# SMS Scam Language Model Evaluation Report

**Model Version:** `sms-lr-v1.0.0`  
**Architecture:** TF-IDF (char_wb n-grams 2-5 + word n-grams 1-2) with balanced Logistic Regression  
**Feature Normalization:** Shorthand expansion, URL tokenization (`urltoken`), number tokenization (`numtoken`)

> [!WARNING]
> **Synthetic Data Over-statement Warning**:
> High evaluation scores on synthetic and templated datasets typically over-state real-world accuracy due to repeating sentence structures and constrained slot vocabulary. The independent hand-written Stress Set (Section C) provides the true indicator of how the model generalizes to unseen scam formulations and everyday human messaging.

---

## 1. Unseen Template Split (Holdout by `template_id`)
Evaluates model performance when trained on one subset of message templates and tested on completely distinct message templates.

| Metric | Score |
|---|---|
| **Precision** | 0.6207 |
| **Recall** | 0.8571 |
| **F1 Score** | 0.7200 |
| **ROC-AUC** | 0.9373 |
| **Brier Score** | 0.1256 |

### Holdout Mistakes (112)
| Text | True Label | Predicted | Prob |
|---|---|---|---|
| `Canara Bank security alert: Unauthorized transaction of Rs 5,000 detected on car` | 1 | 0 | 0.4126 |
| `Axis Bank security alert: Unauthorized transaction of Rs 2,499 detected on card ` | 1 | 0 | 0.3698 |
| `Dear customer, as per RBI guidelines, periodic KYC update is due for ur Canara B` | 0 | 1 | 0.5605 |
| `appointment reminder: ur consultation with dr. sharma is scheduled for tomorrow ` | 0 | 1 | 0.7036 |
| `Aapka HDFC Bank account balance Rs 1,00,000 hai. Surakshit banking ke liye apna ` | 0 | 1 | 0.5180 |
| `aapka sbi account balance rs 499 hai. surakshit banking ke liye apna pin kisi se` | 0 | 1 | 0.5455 |
| `Appointment reminder: Your consultation with Dr. Sharma is scheduled for tomorro` | 0 | 1 | 0.7116 |
| `ICICI Bank security alert: Unauthorized transaction of Rs 2,499 detected on card` | 1 | 0 | 0.4168 |
| `Dear customer, as per RBI guidelines, periodic KYC update is due for your Kotak ` | 0 | 1 | 0.5584 |
| `Appointment reminder: Your consultation with Dr. Sharma is scheduled for tomorro` | 0 | 1 | 0.7036 |

---

## 2. 5-Fold GroupKFold Cross-Validation (by `template_id`)
Cross-validation ensuring that every template group is isolated in the validation fold.

| Metric | Mean | Std Dev |
|---|---|---|
| **Precision** | 0.7472 | ± 0.0957 |
| **Recall** | 0.8956 | ± 0.0635 |
| **F1 Score** | 0.8117 | ± 0.0699 |
| **ROC-AUC** | 0.9470 | ± 0.0328 |
| **Brier Score** | 0.1250 | ± 0.0397 |

---

## 3. Independent Hand-Written Stress Set (50 Samples)
Evaluation on 50 curated real-world and challenging edge-case messages authored outside the template generator.

| Metric | Score |
|---|---|
| **Precision** | 0.8333 |
| **Recall** | 1.0000 |
| **F1 Score** | 0.9091 |
| **ROC-AUC** | 1.0000 |
| **Brier Score** | 0.0959 |

### Stress Set Mistakes (5)
| Text | Category | True | Pred | Prob |
|---|---|---|---|---|
| `Welcome to SBI! Your new account has been activated. Visit branch to collect cheque book.` | banking | 0 | 1 | 0.5893 |
| `Your Amazon Prime subscription will renew in 3 days. Card will be charged 1499.` | subscription | 0 | 1 | 0.5228 |
| `Flight 6E-204 boarding has started at Gate 14. Have a safe journey.` | travel | 0 | 1 | 0.5362 |
| `Zomato Gold membership activated for 3 months.` | subscription | 0 | 1 | 0.5264 |
| `Your EPF passbook has been updated with monthly contribution of Rs 3,600.` | government | 0 | 1 | 0.5740 |

---

## 4. Optional Real Messages
Dataset `real_messages.csv` not provided; evaluation omitted.

---

## 5. Architectural Guardrails
1. **Never High Severity Solo**: The ML prediction produces at most a `medium` severity evidence item (when probability >= 0.85). It can never trigger a "Likely scam" (`malicious`) verdict on its own.
2. **Resilience**: Shorthand terms (`ur`, `u`, `a/c`, `pls`, `blkd`, `updt`) are normalized before vectorization.
3. **Graceful Degradation**: If `models/sms_model.joblib` cannot be loaded, the rule-based SMS service continues operating without interruption.
