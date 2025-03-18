# 악성코드 탐지를 위한 YARA룰 생성

## 프롬프트
```
악성코드를 탐지하는 yara룰을 만들거야. lockbit랜섬웨어를 탐지할거야. 악성코드 샘플도 만들어주고 그것을 탐지하는 yara룰도 만들어줘.
```

![image-20250318174556911](C:\Users\abcd\AppData\Roaming\Typora\typora-user-images\image-20250318174556911.png)

## 실습
#### 0. YARA 설치 확인
    ```bash
    yara --version
    ```
    YARA가 설치되어있지 않다면 아래 사항 확인
    ```bash
    pip install yara-python  # Python 환경용
    sudo apt install yara    # Ubuntu
    brew install yara        # Mac
    ```
    - python을 통해 설치하다 아래 에러가 발생하는 경우 C++ 14.0 설치 필요
        error: Microsoft Visual C++ 14.0 or greater is required.

#### 1. YARA 룰 파일 저장
    ```bash
    nano detect_lockbit_v2.yara 
    ```
    내용을 붙여넣고 저장 (Ctrl + X, Y, Enter)

#### 2. YARA 탐지 테스트 실행
    ```bash
    yara detect_lockbit_v2.yara lockbit_sample_v2.bin
    ```
    ✅ 탐지 성공 시 출력 예시
    ```plaintext
    Detect_LockBit_Ransomware lockbit_sample_v2.bin
    ```
    ✅ 탐지 실패 시 출력 예시
    ```plaintext
    (No output)
    ```



