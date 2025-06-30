# log_analyzer
# log-parser

Objective:

- Parse .vlog security log files.
- Extract structured fields (id, timestamp, event_type, user, ip, path, etc.).
- Handle malformed lines gracefully with clear error tagging.
- Save clean, structured CSV reports for further timeline and anomaly analysis.

 How It Works:
 
1️) Reads all .vlog files from the user specified directory
2️) Parses each line to extract:

Log ID (0xabc123...)
Timestamp (converted to integer)
Event Type (XR-EXEC, XR-DEL, XR-FILE, etc.)
User (if available)
IP address (if available)
File path (if available)
Process ID (if available)

3️) Skips lines that do not match the expected pattern, tagging them as "ERROR" in the CSV for later review.
4️) Saves output to user specified directory

 How to Run:
 
1️)Open VS Code or your terminal.
2️)Ensure Python is installed (python --version).
3️) Run the script:  python log_parser.py
4️) After execution:
 Check log_analysis_report.csv in LOG ANALYSIS folder.

Example CSV Columns:

id	     timestamp	event_type	action	user	path	          ip	pid	status	error	raw
0x1abc...	172342342	XR-EXEC	     RUN	  alice	/usr/bin/bash	
