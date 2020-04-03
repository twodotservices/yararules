rule testing_others_rule
{
    meta:
        author = "Sunil Kumar https://2dots.io"
        description = "testing_others_rule"

    strings:
        $str = "this is others testing string"

    condition:
        $str
}