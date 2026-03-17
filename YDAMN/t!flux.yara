rule Tiflux_Agent
{
    meta:
        author = "Dylan"
        description = "ids tiflux agent abuse"

    strings:
	$name = "TiAgent.exe" ascii wide
	$dom1 = "agent.tiflux.com" ascii wide
        $dom2 = "app.tiflux.com" ascii wide
	
    condition:
        any of them
}
