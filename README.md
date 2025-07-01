# log_analyzer
log timeline

📌 Overview
This module generates a structured, chronological timeline from raw .vlog forensic log files, supporting digital forensics and incident response workflows.

By transforming unstructured logs into clean CSV timelines, it enables clear investigation of event sequences, user actions, and potential incidents.

🚀 Features
✅ Batch parsing of multiple .vlog files
✅ Extracts timestamp, event type, user, IP, file path, and category
✅ Converts raw epoch timestamps to readable datetimes
✅ Outputs an organized timeline.csv
✅ Clear console logging throughout execution

🛠️ What This Script Does
Loads multiple .vlog files from your provided folder.

Parses each log line into structured data fields.

Normalizes timestamps to create a unified timeline.

Sorts all events chronologically for clarity.

Saves results as a CSV file for direct analysis or ingestion into forensic tools.

⚙️ Usage
Run the script using:


python generate_timeline.py <path_to_log_folder>


Column       Description

timestamp    	Original epoch timestamp
datetime     	Normalized, human-readable datetime
event_type   	Extracted event type
user	        Username associated with the event
ip	          Involved IP address (if any)
file_path	    Accessed file or process path (if any)
category	    Categorized as network, user, file, or process

💡 Why Timeline Analysis
A clear event timeline helps:

✅ Reconstruct the sequence of user or attacker activities
✅ Identify suspicious or unusual events in context
✅ Correlate activities across users and systems
✅ Accelerate investigations during incident response

📈 Recommended Next Steps
Use timeline.csv with visualization or anomaly detection tools.

Import into Excel, pandas, or SIEM dashboards for deeper filtering and correlation.

Pair with your anomaly detection modules to tag suspicious spikes automatically.

🤝 Contributing
If you would like to add advanced parsing features, automated tagging, or direct visualization integrations, feel free to fork the repository and submit a pull request.
