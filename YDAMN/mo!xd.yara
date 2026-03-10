rule Moixd_Stealer
{
    meta:
        author = "Dylan"
        description = "Identifies common strings found in moixd infostealer"

    strings:
        $string1 = "Moixd stealer"
        $string2 = /.+domain.+name.+path.+secure.+httpOnly.+expirationDate.+value/
    condition:
        any of them
}
