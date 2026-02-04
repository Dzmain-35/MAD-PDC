import "pe"

rule Mal_Faronics_Deploy_RAT
{
    meta:
        description = "Identifies CWRAT malware"
    strings:
        $str1 = "faronics-deploy-na-production"
        $str2 = "FaronicsDeployAgent" nocase
        $ip1 = "52.41.91.1"
    condition:
        2 of them
}


rule Mal_Faronics_Deploy_RAT_IMPHASH
{
    meta:
        description = "Identifies CWRAT malware"
        imphash = "63c11544893457fb321a43dc42728c6a"
    condition:
        pe.imphash() == "63c11544893457fb321a43dc42728c6a"
}
