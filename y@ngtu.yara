rule Yangtu_RAT
{
    meta:
        author = "Dylan"
        description = "IDs Yangtu/SysAid RMM abused malware"

    strings:
        $string1 = "yangtusoft.cn"


    condition:
        any of them
}
