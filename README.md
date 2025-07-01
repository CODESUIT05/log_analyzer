# log_analyzer
#log anamoly detection
Log Anomaly Detection
This module performs forensic anomaly detection on .vlog log files, identifying suspicious spikes in event frequency for effective digital forensics and incident response.

Features
✅ Parses .vlog forensic logs and extracts structured event data.
✅ Generates a clean, chronological timeline.csv of log events.
✅ Uses rolling mean thresholding to detect spikes in event frequency.
✅ Saves detected anomalies to alerts.csv for further investigation.
✅ Prints a clear forensic summary for fast analyst insights.

Requirements
Python 3.9+

pandas

No additional external visualization libraries required for this module.

Install dependencies if needed:
pip install pandas
Usage
Run the module via the terminal:


python log_anomaly_detection.py <path_to_log_folder>
Replace <path_to_log_folder> with the directory containing your .vlog log files.

Output
After running, the following files will be generated in your current working directory:

timeline.csv: Chronologically sorted forensic log data.

alerts.csv: Contains timestamps and event counts where anomalies were detected.

A clean forensic summary will also be printed in your console, showing:

Total events parsed

Unique users and samples

Event types observed

Detected categories (network, user, file, process)

Time range of logs analyzed

How Anomalies Are Detected
Groups logs by 1-minute intervals.

Calculates a rolling mean over 5-minute windows.

Flags intervals where the event count exceeds 1.5x the rolling mean as anomalies.

This enables rapid detection of suspicious spikes in activity that may indicate attacks, scans, or insider threats.

Recommended Workflow
1️⃣ Collect .vlog files in a folder.
2️⃣ Run the anomaly detection module on the folder.
3️⃣ Review alerts.csv for spikes to investigate suspicious activity.
4️⃣ Review timeline.csv for a complete event timeline.
5️⃣ Use findings in your digital forensic reports or incident response workflow.

