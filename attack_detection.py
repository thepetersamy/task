import re
from datetime import datetime

# Regular expression to parse log lines, split for readability
pattern = re.compile(
    r'(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3}) - '                     # Client IP
    r'(?P<cache_status>\w+) \['                                     # Cache status
    r'(?P<timestamp>[^\]]+)\] '                                     # Timestamp
    r'"(?P<host>[^"]+)" '                                           # Host
    r'"(?P<method>\w+) (?P<url>[^ ]+) (?P<protocol>[^"]+)" '        # Method, URL, Protocol
    r'(?P<status_code>\d{3}) '                                      # HTTP status code
    r'(?P<bytes_sent>\d+) '                                         # Bytes sent
    r'(?P<request_time_ms>\d+) '                                    # Request time
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" '               # Referrer and User Agent
    r'"(?P<extra_dash>[^"]*)" "(?P<upstream_addr>[^"]+)" '          # Extra dash and upstream address
    r'cc="(?P<country_code>\w+)" '                                  # Country code
    r'rt=(?P<rt>[\d.]+) '                                           # Response time
    r'uct="(?P<uct>[\d.]+)" uht="(?P<uht>[\d.]+)" '                 # Upstream connect/header time
    r'urt="(?P<urt>[\d.]+)" ucs="(?P<ucs>\d+)"'                     # Upstream response/cache status
)

def parse_log_line(log_line):
    match = pattern.match(log_line)
    if match:
        data = match.groupdict()
        try:
            # Parse the timestamp
            timestamp = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            timestamp = None
        return {
            'timestamp': timestamp,
            'status': int(data['status_code']),
            'ip': data['client_ip'],
            'url': data['url']
        }
    return None

def is_error_status(status):
    return 400 <= status <= 599

def detect_suspicious_ips(log_file):
    """
    - high request volume
    - frequent error responses
    - repeated access to sensitive endpoints
    - rate-limited IPs (status code 429)
    """
    ip_requests = {}
    ip_errors = {}
    ip_sensitive_access = {}
    ip_rate_limited = {}
    sensitive_endpoints = ['/login', '/api']

    with open(log_file, 'r') as f:
        for line in f:
            log_data = parse_log_line(line)
            if log_data:
                ip = log_data['ip']
                if ip not in ip_requests:
                    ip_requests[ip] = 0
                    ip_errors[ip] = 0
                    ip_sensitive_access[ip] = 0
                    ip_rate_limited[ip] = 0

                
                ip_requests[ip] += 1

                if is_error_status(log_data['status']):
                    ip_errors[ip] += 1

                if any(endpoint in log_data['url'] for endpoint in sensitive_endpoints):
                    ip_sensitive_access[ip] += 1

                if log_data['status'] == 429:
                    ip_rate_limited[ip] += 1

    return ip_requests, ip_errors, ip_sensitive_access, ip_rate_limited

def generate_report(ip_requests, ip_errors, ip_sensitive_access, ip_rate_limited):
    report = []
    rate_limited_ips = []
    for ip in ip_requests:
        if ip_requests[ip] > 100 or ip_errors[ip] > 50 or ip_sensitive_access[ip] > 50 or ip_rate_limited[ip] > 0:
            report.append({
                'ip': ip,
                'total_requests': ip_requests[ip],
                'error_responses': ip_errors[ip],
                'sensitive_access': ip_sensitive_access[ip],
                'rate_limited': ip_rate_limited[ip]
            })
        if ip_rate_limited[ip] > 0:
            rate_limited_ips.append(ip)
    return report, rate_limited_ips

def main(log_file):
    """
    Main function to detect suspicious IPs and print the final summary.
    """
    ip_requests, ip_errors, ip_sensitive_access, ip_rate_limited = detect_suspicious_ips(log_file)
    report, rate_limited_ips = generate_report(ip_requests, ip_errors, ip_sensitive_access, ip_rate_limited)

    # Print total number of suspicious IPs
    print(f"Total Suspicious IPs Detected: {len(report)}")

    # Sort the report based on error responses and sensitive access
    sorted_report = sorted(report, key=lambda x: (x['error_responses'], x['sensitive_access'], x['rate_limited']), reverse=True)

    # Print the top 5 offending IPs
    print("Top 5 Offending IPs:")
    print(f"{'IP Address':<20} {'Total Requests':<15} {'Error Responses':<15} {'Sensitive Access':<15} {'Rate Limited':<15}")
    for entry in sorted_report[:5]:
        print(f"{entry['ip']:<20} {entry['total_requests']:<15} {entry['error_responses']:<15} {entry['sensitive_access']:<15} {entry['rate_limited']:<15}")

    # Print the list of rate-limited IPs
    print("\nIPs that were rate limited (received status code 429):")
    for ip in rate_limited_ips:
        print(ip)

if __name__ == "__main__":
    log_file = 'nginx_access.log'  # Replace with your log file path
    main(log_file)

