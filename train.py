import os
import glob
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

DATA_DIR = "data"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "xss_detector.joblib")

def find_csv():
    files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not files:
        raise FileNotFoundError("No CSV found. Put your Kaggle CSV inside the data/ folder.")
    return files[0]

def main():
    csv_path = find_csv()
    print(f"Loading: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    if "Sentence" not in df.columns or "Label" not in df.columns:
        raise ValueError(f"Expected Sentence and Label columns. Found: {list(df.columns)}")

    df = df[["Sentence", "Label"]].copy()
    df["Sentence"] = df["Sentence"].fillna("").astype(str).str.strip()
    df["Label"] = pd.to_numeric(df["Label"], errors="coerce")
    df = df.dropna(subset=["Sentence", "Label"])
    df = df[df["Sentence"] != ""]
    df = df[df["Label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["Sentence", "Label"]).reset_index(drop=True)

    print(f"Usable rows: {len(df)}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["Sentence"], df["Label"].astype(int),
        test_size=0.20, random_state=42, stratify=df["Label"]
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5),
            min_df=2, sublinear_tf=True, max_features=100000
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced"
        ))
    ])

    print("Training...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("\n===== RESULTS =====")
    print(f"Accuracy : {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1 Score : {f1_score(y_test, predictions, zero_division=0):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["SAFE", "XSS"], zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")

if __name__ == "__main__":
    main()
