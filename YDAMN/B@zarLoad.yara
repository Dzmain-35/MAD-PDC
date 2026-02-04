rule Mal_Bazar_Loader
{
meta:
	description = "Identifies BazarLoader malware"
strings: 
    $str1 = "_rtl.dll"
	$str2 = "bazar.php"
	$str3 = "GetDeepDVCState"
	$domain1 = "bazarunet"
	$domain2 = "greshunka"
	
condition:
  any of them
	
}