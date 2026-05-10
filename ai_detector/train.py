import json
import time
import warnings
from pathlib import Path
from urllib.parse import unquote_plus

import joblib
import numpy as np
import pandas as pd

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")

BASE_DIR  = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR.parent / "data.jsonl"
if not DATA_FILE.exists():
    alt = BASE_DIR / "data.jsonl"
    if alt.exists():
        DATA_FILE = alt

MODEL_OUT = BASE_DIR.parent / "waf.pkl"

def preprocess(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)

    
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded

    
    text = " ".join(text.split())

    return text.lower()

def load_jsonl(path: Path) -> pd.DataFrame:
    records = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return pd.DataFrame(records)


print(f"[*] Loading data from {DATA_FILE} …")
df = load_jsonl(DATA_FILE)

print(f"    {len(df):,} samples | labels: {df['label'].value_counts().to_dict()}")

df["body"] = df["body"].astype(str).apply(preprocess)

X = df["body"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

features = FeatureUnion([
    (
        "char_wb",
        TfidfVectorizer(
            analyzer="char_wb",      
            ngram_range=(3, 6),      
            lowercase=True,
            max_features=150_000,
            sublinear_tf=True,       
        ),
    ),
    (
        "word",
        TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            lowercase=True,
            max_features=50_000,
            sublinear_tf=True,
        ),
    ),
])

base_clf = LinearSVC(class_weight="balanced", max_iter=2000)
calibrated = CalibratedClassifierCV(base_clf, cv=3, method="sigmoid")

pipeline = Pipeline([
    ("features", features),
    ("clf",      calibrated),
])

param_dist = {
    
    "clf__estimator__C":                  [0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
    
    "features__char_wb__ngram_range":     [(2, 5), (3, 6), (3, 7), (2, 6)],
    
    "features__char_wb__max_features":    [100_000, 150_000, 200_000],
    "features__word__max_features":       [30_000, 50_000, 75_000],
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

search = RandomizedSearchCV(
    pipeline,
    param_distributions=param_dist,
    n_iter=20,           
    cv=cv,
    scoring="f1_weighted",
    n_jobs=-1,           
    verbose=1,
    random_state=42,
)

print("\n[*] Running hyper-parameter search (this may take a few minutes) …\n")
t0 = time.time()
search.fit(X_train, y_train)
elapsed = time.time() - t0

print(f"\n[+] Search complete in {elapsed:.1f}s")
print(f"    Best CV F1 (weighted): {search.best_score_:.4f}")
print(f"    Best params: {json.dumps(search.best_params_, indent=6)}")

best_model = search.best_estimator_

print("\n[*] 5-fold cross-validation on training set …")
cv_scores = cross_val_score(best_model, X_train, y_train,
                             cv=cv, scoring="f1_weighted", n_jobs=-1)
print(f"    CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}  "
      f"({cv_scores})")

preds  = best_model.predict(X_test)
probas = best_model.predict_proba(X_test)

print("\n=== Classification Report (held-out test set) ===\n")
print(classification_report(y_test, preds))

print("=== Confusion Matrix ===\n")
labels = sorted(y.unique())
cm = confusion_matrix(y_test, preds, labels=labels)
cm_df = pd.DataFrame(cm, index=[f"true:{l}" for l in labels],
                         columns=[f"pred:{l}" for l in labels])
print(cm_df.to_string())


pos_label = labels[-1]                       
pos_idx   = list(best_model.classes_).index(pos_label)
confidences = probas[:, pos_idx]

print("\n=== 10 Most Uncertain Predictions (attack prob ≈ 0.5) ===\n")
uncertainty = np.abs(confidences - 0.5)
borderline  = np.argsort(uncertainty)[:10]
for i in borderline:
    snippet = X_test.iloc[i][:80].replace("\n", " ")
    print(f"  [{str(preds[i]):>8s} | p={confidences[i]:.3f}]  {snippet}")


artefact = {
    "model":      best_model,
    "classes":    list(best_model.classes_),
    "cv_f1_mean": float(cv_scores.mean()),
    "cv_f1_std":  float(cv_scores.std()),
    "best_params": search.best_params_,
    "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}

joblib.dump(artefact, MODEL_OUT, compress=3)
print(f"\n[+] Model artefact saved → {MODEL_OUT}  "
      f"({MODEL_OUT.stat().st_size / 1024:.1f} KB)")




def predict(texts: list[str], threshold: float = 0.5) -> list[dict]:
    art   = joblib.load(MODEL_OUT)
    mdl   = art["model"]
    clean = [preprocess(t) for t in texts]
    proba = mdl.predict_proba(clean)
    pos   = list(mdl.classes_).index(art["classes"][-1])   

    results = []
    for p in proba:
        attack_prob = p[pos]
        label       = mdl.classes_[np.argmax(p)]
        results.append({
            "label":      label,
            "confidence": round(float(attack_prob), 4),
            "blocked":    attack_prob >= threshold,
        })
    return results