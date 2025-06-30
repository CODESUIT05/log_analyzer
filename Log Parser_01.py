import re
import os
import csv

def parse_log_line(line):
    """Parse a single .vlog log line into structured data."""
    raw_line = line.strip()
    result = {'raw': raw_line}
    
    main_pattern = r'^(0x[0-9a-fA-F]+)\[ts:(\d+)\]\|EVNT:([^!]+)!@(.+)$'
    match = re.match(main_pattern, raw_line)

    if not match:
        result['error'] = 'Main pattern mismatch'
        return result

    hex_id, timestamp_str, event_type, event_data = match.groups()
    result.update({
        'id': hex_id,
        'event_type': event_type
    })

    try:
        result['timestamp'] = int(timestamp_str)
    except ValueError:
        result['error'] = f'Invalid timestamp: {timestamp_str}'

    try:
        if event_type in {'XR-EXEC', 'XR-LOG', 'XR-FILE', 'XR-DEL'}:
            user_match = re.match(r'^(\w+)_usr:([^=]+)=>(.+)$', event_data)
            if user_match:
                result.update({
                    'action': user_match.group(1),
                    'user': user_match.group(2),
                    'path': user_match.group(3)
                })
            else:
                result['error'] = f'Malformed user event: {event_data}'

        elif event_type == 'XR-CONN':
            ip_match = re.match(r'^IP:(\d{1,3}(?:\.\d{1,3}){3})$', event_data)
            if ip_match:
                result['ip'] = ip_match.group(1)
            else:
                result['error'] = f'Malformed IP address: {event_data}'

        elif event_type == 'XR-SHDW':
            pid_match = re.match(r'^KILL_proc:pid(\d+)$', event_data)
            if pid_match:
                result['pid'] = int(pid_match.group(1))
            else:
                result['error'] = f'Malformed process event: {event_data}'

        else:
            result['error'] = f'Unknown event type: {event_type}'

    except Exception as e:
        result['error'] = f'Parsing error: {str(e)}'

    return result

def parse_log_file(file_path):
    """Parse all lines in a single .vlog file."""
    entries = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parsed_entry = parse_log_line(line)
                entries.append(parsed_entry)
    except IOError as e:
        print(f"[File Error] {file_path}: {str(e)}")
    return entries

def create_csv_report(parsed_data, output_filename):
    fieldnames = [
        'id', 'timestamp', 'event_type',
        'action', 'user', 'path',
        'ip', 'pid', 'status',
        'error', 'raw'
    ]

    with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in parsed_data:
            row = entry.copy()
            row['status'] = 'VALID' if 'error' not in entry else 'ERROR'
            writer.writerow(row)

if __name__ == '__main__':
    # Correct paths:
    logs_dir = r"D:\msc dfis\python\log_Analysis\LOG ANALYSIS\logs"
    output_dir = r"D:\msc dfis\python\log_Analysis\LOG ANALYSIS"

    all_entries = []

    if not os.path.isdir(logs_dir):
        print(f"[ERROR] Logs directory does not exist: {logs_dir}")
        exit()

    for filename in os.listdir(logs_dir):
        if filename.endswith('.vlog'):
            file_path = os.path.join(logs_dir, filename)
            print(f"[INFO] Processing: {filename}")
            parsed_entries = parse_log_file(file_path)
            all_entries.extend(parsed_entries)

    output_csv = os.path.join(output_dir, "log_analysis_report.csv")
    create_csv_report(all_entries, output_csv)

    print(f"[SUCCESS] CSV report generated at: {output_csv}")
    print(f"Total entries processed: {len(all_entries)}")
