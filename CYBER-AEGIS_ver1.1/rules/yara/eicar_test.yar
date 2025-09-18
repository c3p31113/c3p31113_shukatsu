rule EICAR_Test_String
{
    meta:
        description = "This rule detects the EICAR standard anti-malware test file."
        author = "EICAR"
        date = "2024-01-01"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar at 0
}