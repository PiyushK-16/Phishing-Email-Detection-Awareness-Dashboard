"""Train + compare models. Run from project root: python -m ml.train_model
Results are produced by actually running this code (see reports/ml_metrics.json)."""
import json, os
import joblib, pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler
from backend.services.features import FEATURE_NAMES
from backend.services.preprocess import load_dataset
from ml.common import row_from_email
from ml.evaluation import evaluate, plot_confusion_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_pipeline(clf):
    prep = ColumnTransformer([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2), "text"),
                              ("num", MinMaxScaler(), FEATURE_NAMES)])
    return Pipeline([("prep", prep), ("clf", clf)])


def main():
    df = load_dataset(os.path.join(ROOT, "data", "phishing_email_dataset.csv"))
    X = pd.DataFrame([row_from_email(r.sender, r.subject, r.body, r.attachment_name) for r in df.itertuples()])
    y = (df["label"] == "PHISHING").astype(int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    models = {"LogisticRegression": LogisticRegression(max_iter=1000),
              "NaiveBayes": MultinomialNB(),
              "RandomForest": RandomForestClassifier(n_estimators=200, random_state=42)}
    results, fitted = {}, {}
    for name, clf in models.items():
        pipe = make_pipeline(clf).fit(Xtr, ytr)
        results[name] = evaluate(yte, pipe.predict(Xte)); fitted[name] = pipe
        print(name, {k: round(v, 3) if isinstance(v, float) else v for k, v in results[name].items()})
    best = max(results, key=lambda k: (results[k]["f1"], results[k]["recall"]))
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True); os.makedirs(os.path.join(ROOT, "models"), exist_ok=True)
    plot_confusion_matrix(results[best], f"{best} (test set)", os.path.join(ROOT, "reports", "confusion_matrix.png"))
    json.dump({"best_model": best, "test_size": len(yte), "results": results},
              open(os.path.join(ROOT, "reports", "ml_metrics.json"), "w"), indent=2)
    joblib.dump(fitted[best], os.path.join(ROOT, "models", "phishing_model.joblib"))
    print(f"Best by F1: {best}. Saved model + reports/. NOTE: synthetic template data -> scores are optimistic.")


if __name__ == "__main__":
    main()
