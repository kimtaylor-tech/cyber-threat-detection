import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

np.random.seed(42)
random.seed(42)

NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
SUSPICIOUS_IPS = ["103.45.67.89", "185.220.101.1", "45.33.32.156", "198.51.100.42", "203.0.113.99"]
USERS = [f"user_{i:03d}" for i in range(1, 30)]
LOCATIONS = ["New York", "Chicago", "Los Angeles", "Houston", "Phoenix"]
SUSPICIOUS_LOCS = ["Moscow", "Beijing", "Pyongyang", "Tehran", "Unknown"]

def generate_logs(n=1000):
    records = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(n):
        is_anomaly = random.random() < 0.08  # 8% anomaly rate
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
        
        if is_anomaly:
            anom_type = random.choice(["brute_force", "unusual_location", "off_hours", "data_exfil", "port_scan"])
            
            if anom_type == "brute_force":
                attempts = random.randint(15, 50)
                ip = random.choice(SUSPICIOUS_IPS)
                location = random.choice(SUSPICIOUS_LOCS)
                bytes_transferred = random.randint(100, 500)
                port = 22
                status = "FAILED"
            elif anom_type == "unusual_location":
                attempts = 1
                ip = random.choice(SUSPICIOUS_IPS)
                location = random.choice(SUSPICIOUS_LOCS)
                bytes_transferred = random.randint(1000, 5000)
                port = 443
                status = "SUCCESS"
            elif anom_type == "off_hours":
                timestamp = base_time + timedelta(hours=random.uniform(2, 4))  # 2-4am
                attempts = random.randint(1, 5)
                ip = random.choice(NORMAL_IPS)
                location = random.choice(LOCATIONS)
                bytes_transferred = random.randint(50000, 200000)
                port = 8080
                status = "SUCCESS"
            elif anom_type == "data_exfil":
                attempts = 1
                ip = random.choice(SUSPICIOUS_IPS)
                location = random.choice(SUSPICIOUS_LOCS)
                bytes_transferred = random.randint(500000, 2000000)
                port = random.choice([21, 25, 1234])
                status = "SUCCESS"
            else:  # port_scan
                attempts = random.randint(20, 100)
                ip = random.choice(SUSPICIOUS_IPS)
                location = random.choice(SUSPICIOUS_LOCS)
                bytes_transferred = random.randint(50, 200)
                port = random.randint(1, 65535)
                status = "FAILED"
            
            records.append({
                "timestamp": timestamp,
                "user": user,
                "source_ip": ip,
                "location": location,
                "login_attempts": attempts,
                "bytes_transferred": bytes_transferred,
                "port": port,
                "status": status,
                "true_label": 1,
                "anomaly_type": anom_type
            })
        else:
            hour = random.randint(7, 20)  # business hours
            timestamp = base_time + timedelta(hours=hour, minutes=random.randint(0,59))
            records.append({
                "timestamp": timestamp,
                "user": user,
                "source_ip": random.choice(NORMAL_IPS),
                "location": random.choice(LOCATIONS),
                "login_attempts": random.randint(1, 3),
                "bytes_transferred": random.randint(500, 10000),
                "port": random.choice([80, 443, 8080]),
                "status": random.choice(["SUCCESS", "SUCCESS", "SUCCESS", "FAILED"]),
                "true_label": 0,
                "anomaly_type": "normal"
            })
    
    df = pd.DataFrame(records)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df

if __name__ == "__main__":
    df = generate_logs(1000)
    df.to_csv("/home/claude/cyber_threat/network_logs.csv", index=False)
    print(f"Generated {len(df)} log entries")
    print(f"Anomalies: {df['true_label'].sum()} ({df['true_label'].mean()*100:.1f}%)")
