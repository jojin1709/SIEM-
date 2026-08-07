const SAMPLE_DATA = {
  'auth-syslog.log': { source_type: 'syslog', lines: [
    "Aug  7 09:12:01 web-01 sshd[1122]: Failed password for invalid user admin from 45.83.12.4 port 51422 ssh2",
    "Aug  7 09:12:03 web-01 sshd[1123]: Failed password for invalid user admin from 45.83.12.4 port 51430 ssh2",
    "Aug  7 09:12:05 web-01 sshd[1124]: Failed password for root from 45.83.12.4 port 51440 ssh2",
    "Aug  7 09:12:07 web-01 sshd[1125]: Failed password for root from 45.83.12.4 port 51448 ssh2",
    "Aug  7 09:12:09 web-01 sshd[1126]: Failed password for invalid user test from 45.83.12.4 port 51456 ssh2",
    "Aug  7 09:12:11 web-01 sshd[1127]: Failed password for invalid user oracle from 45.83.12.4 port 51470 ssh2",
    "Aug  7 09:13:40 web-01 sshd[1140]: Accepted publickey for deploy from 10.0.0.5 port 51900 ssh2",
    "Aug  7 09:14:02 web-01 sudo[1150]: jojin : TTY=pts/0 ; PWD=/home/jojin ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    "Aug  7 09:15:00 db-01 cron[900]: (root) CMD (/usr/local/bin/backup.sh)",
    "Aug  7 09:16:12 web-01 sshd[1160]: Invalid user postgres from 103.21.244.10 port 40011"
  ]},
  'access-nginx.log': { source_type: 'nginx', lines: [
    '203.0.113.5 - - [07/Aug/2026:10:01:02 +0530] "GET /api/products HTTP/1.1" 200 1532 "-" "Mozilla/5.0"',
    '203.0.113.5 - - [07/Aug/2026:10:01:05 +0530] "GET /api/cart HTTP/1.1" 200 843 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:11 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:14 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:18 +0530] "POST /api/checkout HTTP/1.1" 502 340 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:22 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:26 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:31 +0530] "POST /api/checkout HTTP/1.1" 503 180 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:35 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:40 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:45 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [07/Aug/2026:10:02:50 +0530] "POST /api/checkout HTTP/1.1" 500 210 "-" "Mozilla/5.0"',
    '203.0.113.5 - - [07/Aug/2026:10:03:01 +0530] "GET /api/products HTTP/1.1" 200 1532 "-" "Mozilla/5.0"'
  ]},
  'eve.json': { source_type: 'suricata', lines: [
    '{"timestamp":"2026-08-07T10:05:11.223+0530","event_type":"alert","src_ip":"172.16.4.55","dest_ip":"10.0.0.20","host":"ids-01","alert":{"signature":"ET SCAN Nmap Scripting Engine User-Agent Detected","category":"Attempted Information Leak","severity":2}}',
    '{"timestamp":"2026-08-07T10:05:22.881+0530","event_type":"alert","src_ip":"172.16.4.55","dest_ip":"10.0.0.20","host":"ids-01","alert":{"signature":"ET SCAN Possible Nmap User-Agent Observed","category":"Attempted Information Leak","severity":2}}',
    '{"timestamp":"2026-08-07T10:06:03.412+0530","event_type":"alert","src_ip":"185.220.101.4","dest_ip":"10.0.0.20","host":"ids-01","alert":{"signature":"ET MALWARE Cobalt Strike Beacon C2 Traffic","category":"A Network Trojan was detected","severity":1}}',
    '{"timestamp":"2026-08-07T10:06:45.019+0530","event_type":"flow","src_ip":"10.0.0.5","dest_ip":"142.250.183.14","host":"ids-01"}',
    '{"timestamp":"2026-08-07T10:07:12.500+0530","event_type":"alert","src_ip":"185.220.101.4","dest_ip":"10.0.0.20","host":"ids-01","alert":{"signature":"ET EXPLOIT Possible Log4j RCE Attempt","category":"Web Application Attack","severity":1}}'
  ]},
  'winevents.json': { source_type: 'winevent', lines: [
    '{"TimeCreated":"2026-08-07T10:10:01+05:30","Computer":"DC01.corp.local","EventID":4625,"Level":"Warning","Message":"An account failed to log on. Account Name: administrator Source Network Address: 10.10.5.20"}',
    '{"TimeCreated":"2026-08-07T10:10:03+05:30","Computer":"DC01.corp.local","EventID":4625,"Level":"Warning","Message":"An account failed to log on. Account Name: administrator Source Network Address: 10.10.5.20"}',
    '{"TimeCreated":"2026-08-07T10:10:05+05:30","Computer":"DC01.corp.local","EventID":4740,"Level":"Critical","Message":"A user account was locked out. Account Name: administrator Caller Computer Name: WKS-14"}',
    '{"TimeCreated":"2026-08-07T10:11:00+05:30","Computer":"DC01.corp.local","EventID":4624,"Level":"Information","Message":"An account was successfully logged on. Account Name: jsmith"}',
    '{"TimeCreated":"2026-08-07T10:12:30+05:30","Computer":"DC01.corp.local","EventID":1102,"Level":"Critical","Message":"The audit log was cleared. Subject: SYSTEM"}'
  ]}
};

module.exports = { SAMPLE_DATA };
