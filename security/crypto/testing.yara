rule testing_crypto_rule
{
    meta:
        author = "Sunil Kumar https://2dots.io"
        description = "testing_crypto_rule"

    strings:
        $str = "this is crypto testing string"

    condition:
        $str
}