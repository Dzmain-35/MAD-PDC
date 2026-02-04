
import "pe"
import "hash"

rule Mal_Lampion
{
meta:
	description = "Identifies Lampion malware"
strings:
	$str2 = "inde-faturas.com"
	$str3 = "3.144.21.25"
	$str4 = "moduloEXE"
	$str5 = "103.117.141.126"
	$str6 = "142.250.217.164"

condition:
  any of them
	
}

rule Mal_Lampion3
{
    meta:
        description = "Identifies Lampion malware"

    strings:
        // YYYYMMDD followed by up to 50 chars, then "dll"
        $dll = /[12][0-9]{3}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[A-Za-z0-9._-]{0,50}dll/
        $ip1 = "3.144.37.134"

    condition:
        $dll or $ip1
}

