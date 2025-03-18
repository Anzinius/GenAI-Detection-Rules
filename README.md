# GenAI Detection Rules

> 이 레포지토리는 "생성형AI를 활용한 보안 룰 작성" 강의의 실습을 위한 저장소입니다.



```
📂 AI-Security-Rules  # 레포지토리 루트
 ┣ 📂 sigma           # Sigma 룰 저장
 ┃ ┣ 📄 detect_sql_injection.yml
 ┃ ┣ 📄 detect_xss.yml
 ┃ ┣ 📄 detect_ransomware.yml
 ┃ ┗ 📂 converted_queries   # Sigma -> SIEM 변환된 룰
 ┃    ┣ 📄 splunk_sql_injection.spl
 ┃    ┣ 📄 elk_sql_injection.json
 ┃    ┗ 📄 sentinel_xss.kql
 ┣ 📂 yara            # YARA 룰 저장
 ┃ ┣ 📄 detect_malware.yara
 ┃ ┣ 📄 detect_ransomware.yara
 ┃ ┗ 📂 test_samples  # 악성코드 샘플 (예제 파일)
 ┃    ┣ 📄 benign_sample.bin
 ┃    ┗ 📄 malware_sample.bin
 ┣ 📂 snort_suricata  # Snort & Suricata 룰 저장
 ┃ ┣ 📄 snort_sql_injection.rules
 ┃ ┣ 📄 suricata_xss.rules
 ┃ ┗ 📂 test_traffic  # 테스트용 패킷 캡처 (PCAP)
 ┃    ┣ 📄 sql_injection.pcap
 ┃    ┗ 📄 xss_attack.pcap
 ┣ 📂 scripts        # 탐지 테스트용 파이썬 코드
 ┃ ┣ 📄 sigma_log_checker.py
 ┃ ┣ 📄 yara_scan.py
 ┃ ┗ 📄 snort_alert_checker.py
 ┣ 📄 README.md       # 레포지토리 소개 및 사용법
 ┗ 📄 requirements.txt # 필요한 패키지 리스트 (pip install -r requirements.txt)
```

#### **각 파일/폴더의 역할**

- `sigma/`: Sigma 룰, 변환된 쿼리는 하위에 관리
- `yara/`: YARA 룰과 테스트용 악성코드 샘플
- `snort_suricata/`: Snort & Suricata 룰과 테스트 패킷
- `scripts/`: Python 탐지 코드 (`sigmac` 변환, 로그 검사, Snort 탐지 테스트 등)