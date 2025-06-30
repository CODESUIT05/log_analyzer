# Day 6 - Forensic Log Parser Flask App (fixed for NaT issue)

from flask import Flask, request, render_template_string
import pandas as pd
import re
import plotly.express as px
import plotly.io as pio
import base64
from io import BytesIO

app = Flask(__name__)

def parse_vlog_line(line):
    try:
        ts_match = re.search(r'ts:(\d+)', line)
        timestamp = int(ts_match.group(1)) if ts_match else None
        if timestamp is None:
            return None

        evnt_match = re.search(r'EVNT:([^!]+)', line)
        event_type = evnt_match.group(1) if evnt_match else 'UNKNOWN'

        user_match = re.search(r'usr:([^\=>\n]+)', line)
        user = user_match.group(1) if user_match else 'unknown'

        ip_match = re.search(r'IP:([0-9\.]+)', line)
        ip = ip_match.group(1) if ip_match else ''

        file_match = re.search(r'=>([^\n]+)', line)
        file_path = file_match.group(1) if file_match else ''

        category = 'network' if ip else 'user' if user != 'unknown' else 'file' if file_path else 'process'

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

def parse_vlog_files(files):
    all_logs = []
    for file in files:
        content = file.read().decode('utf-8', errors='ignore')
        lines = content.strip().split('\n')
        for line in lines:
            parsed = parse_vlog_line(line)
            if parsed:
                all_logs.append(parsed)
    df = pd.DataFrame(all_logs)
    if not df.empty:
        base_timestamp = df['timestamp'].min()
        df['datetime'] = pd.to_datetime(df['timestamp'] - base_timestamp, unit='s', errors='coerce')
    return df

def fig_to_base64(fig):
    img_bytes = fig.to_image(format="png")
    return base64.b64encode(img_bytes).decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        files = request.files.getlist('files')
        if not files:
            return "Please upload at least one .vlog file."

        df = parse_vlog_files(files)
        df = df.dropna(subset=['datetime'])
        if df.empty:
            return "❌ No valid datetime entries in uploaded files. Please check your .vlog files."

        # Event Frequency Visualization
        freq_df = df.groupby(pd.Grouper(key='datetime', freq='1min')).size().reset_index(name='count')
        fig1 = px.line(freq_df, x='datetime', y='count', title='Event Frequency Over Time')
        fig1_b64 = fig_to_base64(fig1)

        # User Activity Visualization
        user_df = df['user'].value_counts().reset_index()
        user_df.columns = ['user', 'count']
        fig2 = px.bar(user_df, x='user', y='count', title='User Activity')
        fig2_b64 = fig_to_base64(fig2)

        # Anomaly Detection Visualization
        freq_df['rolling_mean'] = freq_df['count'].rolling(window=5, min_periods=1).mean()
        freq_df['anomaly'] = freq_df['count'] > (freq_df['rolling_mean'] * 1.5)
        fig3 = px.scatter(freq_df, x='datetime', y='count', color='anomaly',
                          title='Anomaly Detection', color_discrete_map={True: 'red', False: 'blue'})
        fig3_b64 = fig_to_base64(fig3)

        html_content = f'''
        <html>
        <head><title>Log Analysis Report</title></head>
        <body>
        <h1>📊 Log Analysis Report</h1>
        <h2>1️⃣ Event Frequency Over Time</h2>
        <img src="data:image/png;base64,{fig1_b64}" width="80%">
        <h2>2️⃣ User Activity</h2>
        <img src="data:image/png;base64,{fig2_b64}" width="80%">
        <h2>3️⃣ Anomaly Detection</h2>
        <img src="data:image/png;base64,{fig3_b64}" width="80%">
        <br><br><a href="/">🔄 Upload More Files</a>
        </body></n        </html>
        '''

        return render_template_string(html_content)

    return '''
    <!doctype html>
    <title>Log Analysis Uploader</title>
    <h1>Upload .vlog Files for Analysis</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=files multiple>
      <input type=submit value=Upload>
    </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
