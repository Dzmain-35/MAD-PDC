rule Mal_AutoMox
{
    meta:
        author = "Dylan"
        description = "Identifies Automox RMM powered bt Splashtop"

    strings:
        $string1 = "amagent_watchdog"
        $string2 = "amagent_ui"
	      $string3 = "amagent.ico"
	      $string4 = "C:\\Program Files (x86)\\Automox"
	      $string5 = "osqueryi.exe"
	      $string6 = "automox.age"
	      $string7 = "amagent-watchdog.exe"

    condition:
        2 of them
}
