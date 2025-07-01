import os
import re
import pandas as pd
import matplotlib.pyplot as plt

# Set your paths explicitly
logs_dir = r" "#Enter the directory path of logs 
reports_dir = r" "#enter output directory for reports
os.makedirs(reports_dir, exist_ok=True)

def parse_log_line(line):
    match = re.match(r'^(0x[0-9a-fA-F]+)\[ts:(\d+)\]\|EVNT:([^!]+)!@(.+)$', line.strip())
    if match:
        hex_id, timestamp, event_type, event_data = match.groups()
        return {
            'id': hex_id,
            'timestamp': int(timestamp),
            'event_type': event_type,
            'data': event_data,
            'raw': line.strip()
        }
    else:
        return None

def parse_all_logs(directory):
    entries = []
    for filename in os.listdir(directory):
        if filename.endswith('.vlog'):
            file_path = os.path.join(directory, filename)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = parse_log_line(line)
                    if parsed:
                        entries.append(parsed)
    df = pd.DataFrame(entries)
    return df

def generate_timeline(df):
    df_sorted = df.sort_values(by='timestamp')
    timeline_path = os.path.join(reports_dir, 'timeline.csv')
    df_sorted.to_csv(timeline_path, index=False)
    print(f"✅ Timeline saved: {timeline_path}")

def plot_event_frequency(df):
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    freq = df.groupby(pd.Grouper(key='datetime', freq='1min')).size()
    plt.figure(figsize=(12,6))
    freq.plot(kind='line')
    plt.title('Event Frequency Over Time')
    plt.xlabel('Time')
    plt.ylabel('Event Count')
    plt.tight_layout()
    plot_path = os.path.join(reports_dir, 'event_frequency.png')
    plt.savefig(plot_path)
    plt.close()
    print(f"✅ Event frequency plot saved: {plot_path}")

if __name__ == "__main__":
    print("🔍 Parsing .vlog files for timeline generation...")
    df_logs = parse_all_logs(logs_dir)

    if df_logs.empty:
        print("⚠️ No valid log entries found in the provided .vlog files.")
    else:
        generate_timeline(df_logs)
        plot_event_frequency(df_logs)
        print("✅ Day 2 processing complete. Check the reports folder for timeline and plot.")
