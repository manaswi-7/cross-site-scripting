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
TEST_SIZE = 0.20
RANDOM_STATE = 42

def find_csv():
    files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not files:
        raise FileNotFoundError(
            "No CSV found. Put your Kaggle XSS CSV inside the data/ folder."
        )
    return files[0]

def find_columns(df):
    text_candidates = ["Sentence", "sentence", "Payload", "payload", "Text", "text", "Code", "code"]
    label_candidates = ["Label", "label", "Class", "class", "Target", "target"]

    text_col = next((c for c in text_candidates if c in df.columns), None)
    label_col = next((c for c in label_candidates if c in df.columns), None)

    if text_col is None or label_col is None:
        raise ValueError(
            f"Could not identify text/label columns. Found columns: {list(df.columns)}"
        )
    return text_col, label_col

def clean_label(value):
    s = str(value).strip().lower()
    if s in {"1", "xss", "malicious", "attack", "true"}:
        return 1
    if s in {"0", "benign", "normal", "safe", "false"}:
        return 0
    try:
        return int(float(s))
    except ValueError:
        return None

def main():
    csv_path = find_csv()
    print(f"Loading: {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    print(f"Original rows: {len(df)}")
    print(f"Columns: {list(df.columns)}")

    text_col, label_col = find_columns(df)
    print(f"Text column: {text_col}")
    print(f"Label column: {label_col}")

    df = df[[text_col, label_col]].copy()
    df[text_col] = df[text_col].fillna("").astype(str)
    df["target"] = df[label_col].apply(clean_label)
    df = df[df["target"].isin([0, 1])]
    df = df[df[text_col].str.strip() != ""]
    df = df.drop_duplicates(subset=[text_col, "target"]).reset_index(drop=True)

    print(f"Rows after cleaning: {len(df)}")
    print("Class counts:")
    print(df["target"].value_counts().sort_index())

    X_train, X_test, y_train, y_test = train_test_split(
        df[text_col],
        df["target"],
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["target"]
    )

    # Character n-grams work well for XSS because symbols such as <, >, /, (, )
    # and JavaScript fragments are important parts of the payload.
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            sublinear_tf=True,
            max_features=100000
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ))
    ])

    print("Training model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    print("\n===== RESULTS =====")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["SAFE", "XSS"], zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")

    examples = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "Hello, welcome to my website",
        "This is a normal message"
    ]

    print("\n===== SAMPLE PREDICTIONS =====")
    for text in examples:
        pred = model.predict([text])[0]
        probability = model.predict_proba([text])[0][1]
        print(f"{'XSS' if pred == 1 else 'SAFE':4} | {probability:.3f} | {text}")

if __name__ == "__main__":
    main()
