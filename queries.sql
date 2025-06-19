
SELECT 
    strftime('%H', timestamp) AS hour,
    AVG(response_time_ms) AS avg_response_time
FROM request_logs
GROUP BY hour
ORDER BY avg_response_time DESC
LIMIT 1;

sqlite> SELECT 
   ...>     strftime('%H', timestamp) AS hour,
   ...>     AVG(response_time_ms) AS avg_response_time
   ...> FROM request_logs
   ...> GROUP BY hour
   ...> ORDER BY avg_response_time DESC
   ...> LIMIT 1;
22|905.177514792899

=============================
SELECT 
    ip_address,
    COUNT(*) AS request_count
FROM request_logs
WHERE status_code = 429
GROUP BY ip_address
HAVING request_count > 350;

sqlite> SELECT
   ...>     ip_address,
   ...>     COUNT(*) AS request_count
   ...> FROM request_logs
   ...> WHERE status_code = 429
   ...> GROUP BY ip_address
   ...> HAVING request_count > 350;
119.103.226.136|358
122.157.29.219|363

======================================


SELECT 
    SUM(bytes_sent) AS total_bytes_sent
FROM request_logs
WHERE response_time_ms > 500;

sqlite> SELECT 
   ...>     SUM(bytes_sent) AS total_bytes_sent
   ...> FROM request_logs
   ...> WHERE response_time_ms > 500;
10719865