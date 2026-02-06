rule Ninite_Agent
{
    meta:
        author = "Dylan"
        description = "IDs Ninite Agent malware"

    strings:
        $string2 = "Icon.Ninite.ico"
		$string3 = "Launching Ninite"
		$string4 = "ninite.com"

    condition:
        any of them

}
