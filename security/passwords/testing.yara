rule testing_password_rule
{
    meta:
        author = "Sunil Kumar https://2dots.io"
        description = "testing_password_rule"

    strings:
        $str = "this is password testing string"

    condition:
        $str
}