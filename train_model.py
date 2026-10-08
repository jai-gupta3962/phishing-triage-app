import argparse
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
ROOT=Path(__file__).resolve().parent
def main(csv_path):
    df=pd.read_csv(csv_path).fillna("")
    required={"subject","body","label"}; missing=required-set(df.columns)
    if missing: raise ValueError(f"Dataset is missing columns: {sorted(missing)}")
    text=df["subject"].astype(str)+"\n"+df["body"].astype(str); y=df["label"].astype(int)
    X_train,X_test,y_train,y_test=train_test_split(text,y,test_size=0.2,random_state=42,stratify=y)
    model=Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=120000,sublinear_tf=True,strip_accents="unicode")),("clf",LogisticRegression(max_iter=1000,class_weight="balanced"))])
    model.fit(X_train,y_train); prob=model.predict_proba(X_test)[:,1]
    print(classification_report(y_test,(prob>=0.5).astype(int),digits=4)); print("ROC-AUC:",round(roc_auc_score(y_test,prob),4))
    output=ROOT/"models"/"nlp_pipeline.joblib"; output.parent.mkdir(parents=True,exist_ok=True); joblib.dump(model,output,compress=3); print("Saved:",output)
if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("csv",nargs="?",default=str(ROOT/"data"/"CEAS_08.csv")); main(parser.parse_args().csv)
