rule bitcoin
{
    strings:
    $key = /(L|K)[0-9A-Za-z]{51}/
    $addr1 = /[1-9a-zA-z]{34}(?!OIl)/
    $addr2 = ^5[HJK][1-9A-Za-z][^OIl]{49}

    condition:
    any of them
}
