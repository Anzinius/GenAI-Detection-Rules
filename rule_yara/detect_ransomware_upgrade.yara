import "pe"

rule Detect_LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware variants based on multiple indicators"
        author = "YourName"
        date = "2025-03-14"
        reference = "https://www.lockbitransomware.com"
        version = "2.0"

    strings:
        // 🔹 일반적인 랜섬웨어 키워드
        $s1 = "LockBit" nocase
        $s2 = "ransom note" nocase
        $s3 = "decrypt your files" nocase
        $s4 = "your files have been encrypted" nocase
        $s5 = "contact us for decryption" nocase
        $s6 = "payment in bitcoin" nocase

        // 🔹 파일 확장자 관련 패턴 (LockBit 감염 후 확장자)
        $ext1 = ".lockbit" nocase
        $ext2 = ".abcd" nocase
        $ext3 = ".lockbit2" nocase
        $ext4 = ".lockbit3" nocase

        // 🔹 암호화 관련 Windows API 호출 탐지
        $api1 = "CryptEncrypt" nocase
        $api2 = "CryptGenKey" nocase
        $api3 = "CryptImportKey" nocase
        $api4 = "CryptDestroyKey" nocase

        // 🔹 C2 서버 패턴 (Tor .onion 도메인 포함)
        $c2_1 = ".onion" nocase
        $c2_2 = "lockbit.com" nocase
        $c2_3 = "lockbit[.]top" nocase
        $c2_4 = "lockbit[.]onion" nocase

    condition:
        (
            any of ($s1, $s2, $s3, $s4, $s5, $s6) or   // 랜섬노트 키워드
            any of ($ext1, $ext2, $ext3, $ext4) or     // 감염된 파일 확장자
            any of ($api1, $api2, $api3, $api4) or     // 암호화 관련 API
            any of ($c2_1, $c2_2, $c2_3, $c2_4)        // C2 서버 패턴
        ) or (
            pe.imports("ADVAPI32.dll", "CryptEncrypt") and pe.sections[1].name == ".text"  // PE 파일 내 암호화 API 호출 여부 확인
        )
}
