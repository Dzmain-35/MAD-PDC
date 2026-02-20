rule Soft_Connect_Agent
{
    meta:
        author = "Dylan"
        description = "Identifies abused soft connect agent"

    strings:
        $string1 = "C:\\ProgramData\\SoftConnect"
        $string2 = "SoftConnectUpdate.exe"
		    $string3 = "SoftConnectWatchdog"
		    $ip1 = "185.182.187.151"

    condition:
        any of them
}
