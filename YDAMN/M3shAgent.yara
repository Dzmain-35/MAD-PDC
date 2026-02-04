rule Mal_MeshAgent
{
    meta:
        author = "Your Name"
        description = "Description of what this rule detects"

    strings:
        $string1 = "meshagent64"
	$ip1 = "185.165.169.252"

    condition:
        any of them
}