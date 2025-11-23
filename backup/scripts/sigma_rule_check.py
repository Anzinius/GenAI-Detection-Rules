import re

# 탐지 대상 로그 (Apache access.log 예시)
logs = [
    '192.168.1.10 - - [14/Mar/2025:10:15:23 +0000] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 4523',
    '192.168.1.11 - - [14/Mar/2025:10:16:02 +0000] "POST /login HTTP/1.1" 403 1234',
    '192.168.1.12 - - [14/Mar/2025:10:17:45 +0000] "GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../../../../etc/passwd HTTP/1.1" 200 3000'
]

# Sigma 룰 기반 탐지 패턴 (AI가 생성한 룰에서 추출)
sigma_patterns = [
    r"' OR '1'='1",   # SQL Injection 패턴
    r'UNION SELECT',  # SQL Injection 패턴
    r'../../'         # 디렉토리 트래버설 패턴
]

# 탐지된 로그 출력
for log in logs:
    for pattern in sigma_patterns:
        if re.search(pattern, log):
            print(f"🚨 탐지됨! 로그: {log}")
            break
