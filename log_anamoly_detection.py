import os
import pandas as pd
import re
import plotly.express as px
import plotly.io as pio

def parse_vlog_line(line):
    """Parses a single .vlog line into structured fields."""
    try:
        ts_match = re.search(r'ts:(\d+)', line)
        timestamp = int(ts_match.group(1)) if ts_match else None

        evnt_match = re.search(r'EVNT:([^!]+)', line)
        event_type = evnt_match.group(1) if evnt_match else 'UNKNOWN'

        user_match = re.search(r'usr:([^\=>\n]+)', line)
        user = user_match.group(1) if user_match else 'unknown'

        ip_match = re.search(r'IP:([0-9\.]+)', line)
        ip = ip_match.group(1) if ip_match else ''

        file_match = re.search(r'=>[ ]*([^\n]+)', line)
        file_path = file_match.group(1) if file_match else ''

        category = (
            'network' if ip else
            'user' if user != 'unknown' else
            'file' if file_path else
            'process'
        )

        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'user': user,
            'ip': ip,
            'file_path': file_path,
            'category': category
        }
    except Exception:
        return None

def parse_vlog_files(log_folder):
    """Parses all .vlog files in the provided folder."""
    all_logs = []
    for file in os.listdir(log_folder):
        if file.endswith('.vlog'):
            with open(os.path.join(log_folder, file), 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().strip().split('\n')
                for line in lines:
                    parsed = parse_vlog_line(line)
                    if parsed:
                        all_logs.append(parsed)
    df = pd.DataFrame(all_logs)
    if not df.empty:
        base_timestamp = df['timestamp'].min()
        df['datetime'] = pd.to_datetime(df['timestamp'] - base_timestamp, unit='s')
    return df

def generate_timeline(df, output_dir):
    timeline_path = os.path.join(output_dir, 'timeline.csv')
    if os.path.exists(timeline_path):
        os.remove(timeline_path)  # Ensure previous file does not lock or block
    df_sorted = df.sort_values('datetime')
    df_sorted.to_csv(timeline_path, index=False)
    print(f"✅ Timeline saved: {timeline_path}")


def detect_anomalies(df, output_dir):
    freq_df = df.groupby(pd.Grouper(key='datetime', freq='1min')).size().reset_index(name='count')
    freq_df['rolling_mean'] = freq_df['count'].rolling(window=5, min_periods=1).mean()
    freq_df['anomaly'] = freq_df['count'] > (freq_df['rolling_mean'] * 1.5)

    # Save detected anomalies
    alerts = freq_df[freq_df['anomaly']]
    alerts_csv = os.path.join(output_dir, 'alerts.csv')
    alerts.to_csv(alerts_csv, index=False)
    print(f" Alerts saved: {alerts_csv}")

    # Generate anomaly detection plot
    fig = px.scatter(
        freq_df,
        x='datetime',
        y='count',
        color='anomaly',
        title='Anomaly Detection on Event Frequency',
        color_discrete_map={True: 'red', False: 'blue'}
    )

    anomaly_png = os.path.join(output_dir, 'anomaly_detection.png')
    anomaly_html = os.path.join(output_dir, 'anomaly_detection.html')
    pio.write_image(fig, anomaly_png)
    pio.write_html(fig, anomaly_html)

    print(f" Anomaly detection plot saved: {anomaly_png}, {anomaly_html}")

if __name__ == "__main__":
    # Set paths as variables for clean workflow
    log_folder = r"D:\msc dfis\python\log_Analysis\LOG ANALYSIS\logs"
    output_dir = r"D:\msc dfis\python\log_Analysis\LOG ANALYSIS\reports"
    os.makedirs(output_dir, exist_ok=True)

    print(" Loading and parsing .vlog files for Day 3 anomaly detection...")
    df = parse_vlog_files(log_folder)

    if df.empty:
        print(" No valid .vlog data found for analysis.")
    else:
        generate_timeline(df, output_dir)
        detect_anomalies(df, output_dir)
        print(" done")
