# Cross-Site Scripting (XSS) Attack Detection using Machine Learning

A simple machine-learning project that classifies input text as **SAFE** or **XSS ATTACK**.

## Dataset

This project is designed for the Kaggle **Cross-Site Scripting (XSS) Dataset for Deep Learning**. The commonly used version contains about 13,686 samples with HTML/JavaScript text and binary labels.

Download the CSV from Kaggle and place it here:

`data/xss_dataset.csv`

The training script automatically looks for common column names such as `Sentence` and `Label`.

## Project flow

```
Kaggle XSS Dataset
        ↓
Data cleaning
        ↓
Train/Test split
        ↓
TF-IDF character features
        ↓
Logistic Regression
        ↓
Accuracy / Precision / Recall / F1
        ↓
SAFE or XSS prediction
        ↓
Streamlit demo
```

## 1. Install

```bash
pip install -r requirements.txt
```

## 2. Add dataset

Put the Kaggle CSV inside:

```
data/
└── xss_dataset.csv
```

Do not upload the dataset to GitHub if its license/size does not permit it.

## 3. Train the model

```bash
python train.py
```

The script will:
- load the CSV
- remove empty rows and duplicates
- identify the text and label columns
- split data into 80% training and 20% testing
- convert text into TF-IDF character features
- train Logistic Regression
- print accuracy, precision, recall and F1-score
- print a confusion matrix
- save the model to `models/xss_detector.joblib`

## 4. Run the demo

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal.

## Example

Input:

```html
<script>alert('XSS')</script>
```

Expected type: XSS ATTACK

Input:

```
Hello, welcome to my website
```

Expected type: SAFE

## Technologies

- Python
- Pandas
- Scikit-learn
- TF-IDF
- Logistic Regression
- Streamlit

## Important note

This is a machine-learning classifier for a project/demo. It should not be treated as a complete web application firewall or a guarantee against all XSS variants.
