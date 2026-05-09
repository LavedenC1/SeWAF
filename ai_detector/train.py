import json
from pathlib import Path

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR.parent / "data.jsonl"

if not DATA_FILE.exists():
    alt_file = BASE_DIR / "data.jsonl"
    if alt_file.exists():
        DATA_FILE = alt_file


def load_jsonl(path: Path) -> pd.DataFrame:
    records = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return pd.DataFrame(records)


df = load_jsonl(DATA_FILE)

X = df["body"].astype(str)
y = df["label"]

# data split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# model
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            lowercase=True,
            max_features=100000
        )
    ),
    (
        "clf",
        LinearSVC()
    )
])

# train
print("Training model...")

model.fit(X_train, y_train)

print("Training complete")

# prediction
preds = model.predict(X_test)

print("\n=== Classification Report ===\n")
print(classification_report(y_test, preds))

# export
joblib.dump(model, "waf.pkl")

print("\n[+] Model saved to waf.pkl")