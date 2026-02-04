rule Mal_Heartbeat_RM
{
    meta:
        author = "Dylan	"
        description = "IDs Heart Beat RM malware"

    strings:
        $string1 = "HeartbeatRM" nocase
	$string2 = "HBRM-HELPER.EXE"
	$string3 = "hbrm-helper-x86"
	$url1 = "static.heartbeatrm.com"
	$ip1 = "13.224.125.74"


    condition:
        any of them
}