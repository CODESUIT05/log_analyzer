# day4_suspicious_activity_detection.py

import os
import pandas as pd
import re
import matplotlib.pyplot as plt

# --------------------- CONFIG ---------------------
LOG_DIR = r" "#log directory
OUTPUT_DIR = r" "#output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --------------------- PARSE LOGS ---------------------
def parse_log_line(line):
    try:
        ts_match = re.search(r'ts:(\d+)', line)
        timestamp = int(ts_match.group(1)) if ts_match else None

        evnt_match = re.search(r'EVNT:([^!]+)', line)
        event_type = evnt_match.group(1) if evnt_match else 'UNKNOWN'

        user_match = re.search(r'usr:([^\=>\n]+)', line)
        user = user_match.group(1) if user_match else 'unknown'

        ip_match = re.search(r'IP:([0-9\.]+)', line)
        ip = ip_match.group(1) if ip_match else ''

        file_match = re.search(r'=>([^\n]+)', line)
        file_path = file_match.group(1) if file_match else ''

        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'user': user,
            'ip': ip,
            'file_path': file_path
        }
    except:
        return None

def load_logs(log_dir):
    logs = []
    for file in os.listdir(log_dir):
        if file.endswith('.vlog'):
            with open(os.path.join(log_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = parse_log_line(line.strip())
                    if parsed:
                        logs.append(parsed)
    df = pd.DataFrame(logs)
    if not df.empty:
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    return df

# --------------------- DETECT SUSPICIOUS ACTIVITY ---------------------
def detect_suspicious_activity(df):
    suspicious = []

    # Rule 1: Multiple Sensitive File Modifications
    sensitive_files = ['/etc/passwd', '/etc/shadow', '/bin/', '/sbin/']
    sensitive_mods = df[df['file_path'].str.contains('|'.join(sensitive_files), na=False)]
    if len(sensitive_mods) >= 3:
        user_counts = sensitive_mods['user'].value_counts()
        for user, count in user_counts.items():
            suspicious.append({
                'rule': 'Sensitive File Modifications',
                'user': user,
                'ip': '',
                'timestamp': sensitive_mods[sensitive_mods['user'] == user]['timestamp'].max(),
                'details': f"{count} sensitive files modified by {user}",
                'severity': 'High'
            })

    # Rule 2: Multiple Connections from the Same IP
    ip_group = df[df['ip'] != '']
    ip_counts = ip_group['ip'].value_counts()
    for ip, count in ip_counts.items():
        if count >= 5:
            suspicious.append({
                'rule': 'Multiple IP Connections',
                'user': '',
                'ip': ip,
                'timestamp': ip_group[ip_group['ip'] == ip]['timestamp'].max(),
                'details': f"{count} connections from IP {ip}",
                'severity': 'Medium'
            })

    # Rule 3: High Event Volume
    if len(df) > 1000:
        suspicious.append({
            'rule': 'High Log Volume',
            'user': '',
            'ip': '',
            'timestamp': df['timestamp'].max(),
            'details': f"{len(df)} events detected in total",
            'severity': 'Medium'
        })

    return pd.DataFrame(suspicious)

# --------------------- VISUALIZATION ---------------------
def plot_event_frequency(df):
    freq = df.groupby(pd.Grouper(key='datetime', freq='1Min')).size()
    plt.figure(figsize=(10,5))
    freq.plot(kind='line', title='Event Frequency Over Time')
    plt.xlabel('Time')
    plt.ylabel('Event Count per Minute')
    plt.tight_layout()
    plot_path = os.path.join(OUTPUT_DIR, 'event_frequency.png')
    plt.savefig(plot_path)
    plt.close()
    print(f"Event frequency plot saved: {plot_path}")

# --------------------- MAIN EXECUTION ---------------------
if __name__ == "__main__":
    print(" Suspicious Activity Detection Started...")

    df = load_logs(LOG_DIR)
    if df.empty:
        print("⚠️ No log data found for analysis.")
        exit(0)

    suspicious_df = detect_suspicious_activity(df)

    # Save suspicious activity report
    report_path = os.path.join(OUTPUT_DIR, 'suspicious_report.csv')
    suspicious_df.to_csv(report_path, index=False)
    print(f" Suspicious activity report saved: {report_path}")

    # Save timeline of events
    timeline_path = os.path.join(OUTPUT_DIR, 'timeline04.csv')
    df.sort_values('datetime').to_csv(timeline_path, index=False)
    print(f"Timeline saved: {timeline_path}")

    # Generate and save visualization
    plot_event_frequency(df)

    print("Analysis completed successfully.")
