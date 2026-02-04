rule Mal_TrustConnect
{
    meta:
        author = "Dylan"
        description = "Trust Connect"

    strings:
        $string1 = "TrustConnectWorker" nocase
        $string2 = "trustconnectsoftware.com"
	$ip1 = "178.128.69.245"

    condition:
        any of them
}