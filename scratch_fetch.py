import pandas as pd

url = "https://raw.githubusercontent.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/main/data/CICIDS2017_sample_km.csv"
try:
    df = pd.read_csv(url)
    print("Shape:", df.shape)
    print("Columns:", df.columns.tolist()[:10], "...")
    print("Labels:", df[' Label'].value_counts() if ' Label' in df.columns else df['Label'].value_counts())
    df.to_csv('ml/data/raw/CICIDS2017_sample.csv', index=False)
except Exception as e:
    print("Error:", e)
