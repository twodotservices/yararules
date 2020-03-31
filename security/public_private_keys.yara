rule x509_public_key_infrastructure_cert
{
  meta:
    desc = "X.509 PKI Certificate"
    ext = "crt"
  strings: $a = {30 82 ?? ?? 30 82 ?? ??}
  condition: $a
}
rule pkcs8_private_key_information_syntax_standard
{
  meta:
    desc = "Found PKCS #8: Private-Key"
    ext = "key"
  strings: $a = {30 82 ?? ?? 02 01 00}
  condition: $a
}
rule unencrypted_private_key : plain_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find unencrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and not $content2
}

rule encrypted_private_key : encrypted_privatekey privatekey keycontainer
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find encrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and $content2
}

rule keepass_file : keycontainer keepass
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find keepass containers"
    strings:
        $filemagic_primary = {03 D9 A2 9A}
        $filemagic_secondary = {(67 | 65 | 66 | 55) FB 4B B5}
    condition:
        $filemagic_primary at 0 and $filemagic_secondary at 4
}

rule jks_file : keycontainer java_keystore
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find java keystore containers"
    strings:
        $filemagic = {fe ed fe ed 00 00 00 02}
    condition:
        $filemagic at 0
}

rule encrypted_ppk_file : keycontainer putty encrypted_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find encrypted putty ppk files"
    strings:
        $content = "PuTTY-User-Key-File-2" nocase
        $content2 = "Encryption" nocase
        $content3 = "Private-Lines" nocase
        $content4 = "none" nocase
    condition:
        $content at 0 and $content2 and $content3 and not $content4
}

rule ppk_file : keycontainer putty plain_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find putty ppk files"
    strings:
        $content = "PuTTY-User-Key-File-2" nocase
        $content2 = "Encryption" nocase
        $content3 = "Private-Lines" nocase
        $content4 = "none" nocase
    condition:
        $content at 0 and $content2 and $content3 and $content4
}