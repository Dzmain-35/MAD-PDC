rule Hijack_Loader_Modules
{
    meta:
        author = "Dylan"
        description = "Identifies common modules found in Hijack Loader malware"

    strings:
        $str1 = "TinycallProxy" 
        $str2 = "modCreateProcess"
	$str3 = "LauncherLdr64"
	$str4 = "tinystub"
	$str5 = "CUSTOMINJECTPATH"

    condition:
        all of them
}
