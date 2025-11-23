rule Detect_LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware variants"
        author = "YourName"
        date = "2025-03-14"
        reference = "https://www.lockbitransomware.com"
        version = "1.0"

    strings:
        $s1 = "LockBit" nocase
        $s2 = "CryptEncrypt" nocase
        $s3 = "CryptGenKey" nocase
        $s4 = ".lockbit" nocase
        $s5 = ".abcd" nocase
        $s6 = "ransom note" nocase
        $c2_1 = ".onion" nocase
        $c2_2 = "lockbit.com"

    condition:
        (any of ($s1, $s2, $s3, $s4, $s5, $s6)) or (any of ($c2_1, $c2_2))
}
