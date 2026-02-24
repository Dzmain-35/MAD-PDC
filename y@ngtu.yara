rule Yangtu_RAT
{
    meta:
        author = "Dylan"
        description = "IDs Yangtu/SysAid RMM abused malware"

    strings:
        $name = "yangtusoft"
	    $str1 = "[YTSTATUS]"
	    $str2 = "YTSysConfig.ini"


    condition:
        $name or 2 of ($str*)
}
