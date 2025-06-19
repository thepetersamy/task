'''
TASK:

    - Identify the top 5 IP addresses by request count.
    - Calculate the percentage of requests with status codes in the 400-599 range.
    - Find the average response size in bytes for GET requests.

'''
'''
Output:

logs have been parsed and saved to parsed_logs.csv

top 5 IPs by request count:
client_ip
221.34.171.155    383
145.98.68.30      380
110.105.174.63    361
24.74.238.114     355
32.90.145.204     354
Name: count, dtype: int64

47.29% of requests returned 4xx or 5xx status codes.

Average bytes sent for GET requests: 2537.31
'''
import re
import csv
try:
    import pandas as pd
except ImportError:
    print("ImportError: pandas is not installed. Please install it using 'pip install pandas'")

# Input and output file paths
log_file = "nginx_access.log"
output_file = "parsed_logs.csv"

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

with open(log_file, 'r') as f:
    lines = f.readlines()

with open(output_file, 'w', newline='') as csvfile:
    fieldnames = [
        'client_ip', 'cache_status', 'timestamp', 'host', 'method', 'url', 'protocol',
        'status_code', 'bytes_sent', 'request_time_ms', 'referrer', 'user_agent',
        'upstream_addr', 'country_code', 'rt', 'uct', 'uht', 'urt', 'ucs'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for line in lines:
        match = pattern.search(line)
        if match:
            row = match.groupdict()
            row.pop('extra_dash', None)
            writer.writerow(row)

print(f"logs have been parsed and saved to {output_file}")

df = pd.read_csv(output_file)

df['status_code'] = pd.to_numeric(df['status_code'], errors='coerce')
df['bytes_sent'] = pd.to_numeric(df['bytes_sent'], errors='coerce')

# 1. top 5 IP addresses by request count
top_ips = df['client_ip'].value_counts().head(5)
print("\ntop 5 IPs by request count:")
print(top_ips)

# 2. percentage of requests with status codes 400–599
total = len(df)
errors = df['status_code'].between(400, 599).sum()
error_percentage = (errors / total) * 100
print(f"\n{error_percentage:.2f}% of requests returned 4xx or 5xx status codes.")

# 3. average response size for GET requests
get_requests = df[df['method'] == 'GET']
avg_bytes = get_requests['bytes_sent'].mean()
print(f"\nAverage bytes sent for GET requests: {avg_bytes:.2f}")
