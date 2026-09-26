import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer

def train_models():
    print("Loading data...")
    dataset_path = 'ml/data/raw/synthetic_network_traffic.csv'
    df = pd.read_csv(dataset_path)
    
    print(f"Dataset source: {dataset_path}")
    print(f"Initial Dataset Shape: {df.shape}")
    print(f"Target/label column: 'Label'")
    print(f"Features: {df.columns.drop('Label').tolist()}")
    print(f"Missing Values:\n{df.isnull().sum()}")
    
    # Preprocessing: Replace inf with nan
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Preprocessing: Drop duplicates
    df = df.drop_duplicates()
    print(f"Shape after duplicate removal: {df.shape}")
    print(f"Class Distribution:\n{df['Label'].value_counts()}")
    
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Preprocessing Pipeline (Impute missing -> Scale)
    numeric_features = X.columns.tolist()
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_features)
        ])
    
    # Random Forest Pipeline
    rf_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42))
    ])
    
    print("Training Random Forest Classifier Pipeline...")
    rf_pipeline.fit(X_train, y_train)
    
    y_pred = rf_pipeline.predict(X_test)
    
    print("\n--- Random Forest Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision (macro): {precision_score(y_test, y_pred, average='macro'):.4f}")
    print(f"Recall (macro): {recall_score(y_test, y_pred, average='macro'):.4f}")
    print(f"F1-score (macro): {f1_score(y_test, y_pred, average='macro'):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Isolation Forest Pipeline
    print("\nTraining Isolation Forest...")
    benign_X = X_train[y_train == 'BENIGN']
    iso_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('anomaly', IsolationForest(contamination=0.01, random_state=42))
    ])
    iso_pipeline.fit(benign_X)
    
    # Save Artifacts
    os.makedirs('ml/models', exist_ok=True)
    joblib.dump(rf_pipeline, 'ml/models/rf_pipeline.pkl')
    joblib.dump(iso_pipeline, 'ml/models/isolation_forest_pipeline.pkl')
    print("\nModel pipelines saved successfully to ml/models/")

if __name__ == "__main__":
    train_models()
