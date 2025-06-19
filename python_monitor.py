import re
from datetime import datetime, timedelta
from collections import deque

def parse_log_line(log_line):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] "(\w+\.\w+\.\w+)" "(\w+ /.* HTTP/\d\.\d)" (\d+) (\d+) (\d+)'
    match = re.match(pattern, log_line)
    if match:
        ip, action, timestamp_str, domain, request, status, bytes_sent, unknown = match.groups()
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        return {
            'timestamp': timestamp,
            'status': int(status), # first bug fixed by casting into an int
            'ip': ip
        }
    else:
        return None

def is_error_status(status):
    return status >= 400 and status <= 599

def monitor_logs(log_file):
    window = deque() # sliding window to hold logs for last 5 mins using a double ended queue
    window_duration = timedelta(minutes=5)
    error_threshold = 0.10

    with open(log_file, 'r') as f:
        lines = f.readlines()

    log_entries = []
    for line in lines:
        log_data = parse_log_line(line.strip())
        if log_data:
            log_entries.append(log_data)
        

    log_entries.sort(key=lambda x: x['timestamp']) # sorting by timestamp
    with open('sorted_logs.txt', 'w') as sorted_file: # writing sorted logs to a file
        for log_data in log_entries:
            sorted_file.write(f"{log_data['timestamp']} {log_data['status']} {log_data['ip']}\n")

    error_requests = 0
    total_requests = 0
    
    # iterate over each log line,
    # looks backwards,
    # removes logs where time exceeds 5mins,
    # adds logs to fill 5min time window
    # calculates error for each time window
    for log_data in log_entries:
        timestamp = log_data['timestamp']
        status = log_data['status']

        window.append((timestamp, status))
        
        cutoff = timestamp - window_duration


        if total_requests > 0:
            error_rate = error_requests / total_requests
            if error_rate > error_threshold and window[0][0] < cutoff:
                print(f"Alert! Error rate {error_rate*100:.2f}% exceeds threshold at {window[0][0]}")

        while window and window[0][0] < cutoff:
            if is_error_status(window[0][1]):
                error_requests -= 1
            total_requests -= 1
            window.popleft()

        if is_error_status(status):
            error_requests += 1
        total_requests += 1

monitor_logs('nginx_access.log')




