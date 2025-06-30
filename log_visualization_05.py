# day5_advanced_suspicious_analysis.py

import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from tkinter import Tk, filedialog
from fpdf import FPDF

# --- Parse logs ---
def parse_logs(file_paths):
    entries = []
    for file in file_paths:
        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                ts = pd.NA
                if 'ts:' in line:
                    try:
                        ts = int(line.split('ts:')[1].split(']')[0])
                    except:
                        pass
                evnt = line.split('EVNT:')[1].split('!')[0] if 'EVNT:' in line else 'UNKNOWN'
                user = 'unknown'
                if 'usr:' in line:
                    user = line.split('usr:')[1].split('=')[0]
                ip = ''
                if 'IP:' in line:
                    ip = line.split('IP:')[1].strip()
                path = ''
                if '=>' in line:
                    path = line.split('=>')[1].strip()

                entries.append({
                    'timestamp': ts,
                    'datetime': datetime.fromtimestamp(ts) if pd.notna(ts) else pd.NaT,
                    'event_type': evnt,
                    'user': user,
                    'ip': ip,
                    'file_path': path
                })
    return pd.DataFrame(entries)

# --- Advanced detection rules ---
def detect_suspicious_activities(df):
    suspicious = []

    # Rule: Multiple sensitive modifications by user
    sensitive = df[df['file_path'].str.contains('/etc/passwd|/etc/shadow|/bin/|/sbin/', na=False)]
    for user, group in sensitive.groupby('user'):
        if len(group) >= 3:
            suspicious.append({
                'rule': 'Multiple Sensitive Modifications',
                'user': user,
                'ip': '',
                'timestamp': group['timestamp'].max(),
                'details': f"{len(group)} sensitive modifications by {user}",
                'severity': 'High'
            })

    # Rule: Rapid multi-event activity
    df_sorted = df.sort_values('timestamp')
    for user, group in df_sorted.groupby('user'):
        for idx in range(len(group) - 2):
            window = group.iloc[idx:idx+3]
            if window['timestamp'].iloc[2] - window['timestamp'].iloc[0] <= 120:
                suspicious.append({
                    'rule': 'Rapid Multi-Event Activity',
                    'user': user,
                    'ip': '',
                    'timestamp': window['timestamp'].iloc[2],
                    'details': f"3 events in 2 mins by {user}",
                    'severity': 'Medium'
                })
                break

    # Rule: Multiple connections from same IP
    ips = df[df['ip'] != '']
    for ip, group in ips.groupby('ip'):
        if len(group) >= 5:
            suspicious.append({
                'rule': 'Multiple Connections from IP',
                'user': '',
                'ip': ip,
                'timestamp': group['timestamp'].max(),
                'details': f"{len(group)} connections from {ip}",
                'severity': 'Medium'
            })

    return pd.DataFrame(suspicious)

# --- Generate visualization ---
def generate_visual(df, output_dir):
    if df.empty:
        print("⚠️ No suspicious activities detected, skipping visualization.")
        return
    counts = df['rule'].value_counts()
    plt.figure(figsize=(8, 5))
    counts.plot(kind='bar', color='salmon')
    plt.title('Suspicious Activity Counts by Rule')
    plt.xlabel('Detection Rule')
    plt.ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    img_path = os.path.join(output_dir, 'suspicious_activity_distribution.png')
    plt.savefig(img_path)
    plt.close()
    print(f" Suspicious activity visualization saved: {img_path}")

# --- Generate PDF report ---
def generate_pdf_report(suspicious_df, output_dir):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, "Suspicious Activity Report", ln=True, align='C')
    pdf.ln(10)

    if suspicious_df.empty:
        pdf.cell(0, 10, "No suspicious activities detected.", ln=True)
    else:
        for idx, row in suspicious_df.iterrows():
            pdf.multi_cell(0, 8,
                f"Rule: {row['rule']}\n"
                f"User: {row['user']}\n"
                f"IP: {row['ip']}\n"
                f"Timestamp: {row['timestamp']}\n"
                f"Details: {row['details']}\n"
                f"Severity: {row['severity']}\n"
                "------------------------------"
            )
            pdf.ln(2)

    report_path = os.path.join(output_dir, 'suspicious_activity_report.pdf')
    pdf.output(report_path)
    print(f" PDF report saved: {report_path}")

# --- Main execution ---
if __name__ == "__main__":
    print("Select .vlog files for Day 5 advanced suspicious activity analysis...")

    Tk().withdraw()
    file_paths = filedialog.askopenfilenames(title="Select .vlog files for Day 5", filetypes=[("VLOG files", "*.vlog")])
    if not file_paths:
        print(" No files selected, exiting.")
        exit()

    df = parse_logs(file_paths)
    if df.empty:
        print(" No valid logs found in the selected files.")
        exit()

    suspicious_df = detect_suspicious_activities(df)

    output_dir = os.path.join(os.getcwd(), 'reports_day5')
    os.makedirs(output_dir, exist_ok=True)

    suspicious_csv = os.path.join(output_dir, 'day5_suspicious_report.csv')
    suspicious_df.to_csv(suspicious_csv, index=False)
    print(f"Detailed suspicious activity CSV saved: {suspicious_csv}")

    generate_visual(suspicious_df, output_dir)
    generate_pdf_report(suspicious_df, output_dir)

    print(" analysis completed. Check your 'reports_5' folder for CSV, visualization, and PDF report.")
