rule icedid_behavior
{
    meta:
        description = "Identifies behavior associated with IcedID malware"
        author = "Fevar54"
    
    strings:
        $string1 = "iceid"
        $string2 = "drop_x"
        $string3 = "spreader"
        $string4 = "evade_sbox"

    condition:
        any of ($string*) or all of them
}
