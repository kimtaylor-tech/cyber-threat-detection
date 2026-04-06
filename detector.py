import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')

def load_and_preprocess(path):
    df = pd.read_csv(path, parse_dates=["timestamp"])
    
    df["hour"] = df["timestamp"].dt.hour
    df["is_off_hours"] = ((df["hour"] < 7) | (df["hour"] > 20)).astype(int)
    df["is_suspicious_ip"] = df["source_ip"].apply(
        lambda x: 1 if not x.startswith("192.168") else 0
    )
    df["is_suspicious_location"] = df["location"].apply(
        lambda x: 1 if x in ["Moscow", "Beijing", "Pyongyang", "Tehran", "Unknown"] else 0
    )
    df["is_failed"] = (df["status"] == "FAILED").astype(int)
    df["high_bytes"] = (df["bytes_transferred"] > 100000).astype(int)
    df["unusual_port"] = df["port"].apply(
        lambda x: 1 if x not in [80, 443, 8080, 22] else 0
    )
    
    features = [
        "login_attempts", "bytes_transferred", "port",
        "hour", "is_off_hours", "is_suspicious_ip",
        "is_suspicious_location", "is_failed", "high_bytes", "unusual_port"
    ]
    
    return df, features

def train_model(df, features):
    X = df[features].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    
    predictions = model.predict(X_scaled)
    # IsolationForest: -1 = anomaly, 1 = normal → convert to 1/0
    df["predicted_anomaly"] = (predictions == -1).astype(int)
    df["anomaly_score"] = -model.score_samples(X_scaled)  # higher = more anomalous
    
    # Assign threat type based on rules + score
    def classify_threat(row):
        if row["predicted_anomaly"] == 0:
            return "Normal"
        if row["login_attempts"] > 10:
            return "Brute Force"
        if row["is_suspicious_location"] and row["bytes_transferred"] > 100000:
            return "Data Exfiltration"
        if row["is_suspicious_location"]:
            return "Unusual Location"
        if row["is_off_hours"]:
            return "Off-Hours Activity"
        if row["unusual_port"] and row["login_attempts"] > 15:
            return "Port Scan"
        return "Suspicious Activity"
    
    df["threat_type"] = df.apply(classify_threat, axis=1)
    
    # Severity
    def get_severity(row):
        if row["predicted_anomaly"] == 0:
            return "None"
        score = row["anomaly_score"]
        if score > 0.15:
            return "Critical"
        elif score > 0.10:
            return "High"
        elif score > 0.05:
            return "Medium"
        return "Low"
    
    df["severity"] = df.apply(get_severity, axis=1)
    
    return df, model, scaler, features

def evaluate(df):
    y_true = df["true_label"]
    y_pred = df["predicted_anomaly"]
    print("\n=== Model Performance ===")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Anomaly"]))
    return classification_report(y_true, y_pred, output_dict=True)

if __name__ == "__main__":
    df, features = load_and_preprocess("/home/claude/cyber_threat/network_logs.csv")
    df, model, scaler, features = train_model(df, features)
    evaluate(df)
    df.to_csv("/home/claude/cyber_threat/analyzed_logs.csv", index=False)
    joblib.dump({"model": model, "scaler": scaler, "features": features}, 
                "/home/claude/cyber_threat/model.pkl")
    print(f"\nDetected {df['predicted_anomaly'].sum()} threats out of {len(df)} events")
    print("Threat breakdown:")
    print(df[df['predicted_anomaly']==1]['threat_type'].value_counts())
