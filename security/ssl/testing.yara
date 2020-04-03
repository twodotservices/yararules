rule testing_ssl_rule
{
    meta:
        author = "Sunil Kumar https://2dots.io"
        description = "testing_ssl_rule"

    strings:
        $str = "this is ssl testing string"

    condition:
        $str
}