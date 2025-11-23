# Sigma 룰 생성해서 SIEM에 적용하기

## 실습
#### 실습 환경 준비
1. python 설치 + 환경변수 추가
2. sigmatools 패키지 설치 + 환경변수 추가
    ```bash
    pip install sigmatools ## 설치
    pip show sigmatools ## 설치 확인
    ```


#### 실습1. Sigma → Splunk 변환
1. 명령어 실행
    ```bash
    sigmac --target splunk --config windows-audit detect_sql_injection.yml
    ```
2. 결과 값으로 나온 쿼리를 splunk에서 실행
    ```powershell
    (cs-uri-query="' OR '1'='1" OR cs-uri-query="\" OR \"1\"=\"1" OR cs-uri-query="UNION SELECT")
    ```


#### 실습2. Sigma → ELK (Elasticsearch) 변환
1. 명령어 실행
    ```bash
    sigmac --target es-dsl --config logstash-windows detect_sql_injection.yml
    ```
2. 결과 값으로 나온 JSON을 Kibana의 Dev Tools에 입력
    ```json
    {
    "query": {
    	"constant_score": {
     		"filter": {
        		"bool": {
          			"should": [
                    {
                      "match_phrase": {
                        "cs-uri-query": "' OR '1'='1"    
                      }
                    },
                    {
                      "match_phrase": {
                        "cs-uri-query": "\" OR \"1\"=\"1"
                      }
                    },
                    {
                      "match_phrase": {
                        "cs-uri-query": "UNION SELECT"   
                      }
                    }
                  ]
                }
            }
        }
    }
    }    
    ```



## `sigmac` 명령어 옵션
- `--target` 또는 `-t` 옵션
    splunkxml,limacharlie,powershell,hedera,dnif,netwitness,logpoint,datadog-logs,humio,csharp,carbonblack,arcsight,es-rule-eql,es-qs-lr,grep,ala,lacework,qualys,fieldlist,sysmon,graylog,es-qs,sumologic-cse,sqlite,es-dsl,splunkdm,netwitness-epl,crowdstrike,qradar,fortisiem,logiq,chronicle,fireeye-helix,kibana-ndjson,es-rule,kibana,arcsight-esm,ee-outliers,sentinel-rule,sql,xpack-watcher,uberagent,splunk,ala-rule,opensearch-monitor,sumologic-cse-rule,hawk,devo,elastalert,streamalert,sumologic,stix,elastalert-dsl,athena,es-eql,mdatp

- `--config` 또는 `-c` 옵션
    ```powershell
              elk-defaultindex : ELK default indices logstash-* and filebeat-*
     elk-defaultindex-filebeat : ELK default indices filebeat-*
     elk-defaultindex-logstash : ELK default indices logstash-*
                     elk-linux : ELK Linux Indices and Mappings
                   elk-windows : ELK Windows Indices and Mappings
                elk-winlogbeat : ELK Ingested with Winlogbeat
             elk-winlogbeat-sp : ELK Ingested with Winlogbeat
                    powershell : Conversion of Generic Rules into Powershell Specific EventID Rules
                splunk-windows : Splunk Windows log source conditions
          splunk-windows-index : Splunk Windows index and EventID field mapping
                   splunk-zeek : Splunk Zeek sourcetype mappings
                        sysmon : Conversion of Generic Rules into Sysmon Specific Rules
                 windows-audit : Conversion for Windows Native Auditing Events
              windows-services : Conversion of Generic Windows Service to Channel and EventID
    ```