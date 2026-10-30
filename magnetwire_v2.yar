/*
    Magnet Wire v2 - detection rules
    Date: 2026-10-29

    Scope:
      - stage-2 decrypted shellcode / memory dumps (constants)
      - original loader PDB path
      - decrypted DMV2 configuration in memory

    Note: the "Magnet Wire v2 ..." handshake labels are assembled at
          runtime from immediates and do not appear as plaintext strings
          in the file. Match the constants or memory artifacts instead.
*/

rule MagnetWire_v2_stage2_consts
{
    meta:
        description = "Magnet Wire v2 stage-2 shellcode constants"
        date = "2026-10-29"
        severity = "high"
    strings:
        $c1 = { 51 86 f4 b1 }   // 0xb1f48651 - API/module hash init
        $c2 = { ab 01 00 01 }   // 0x010001ab - hash multiplier
        $c3 = { ce fa de c0 }   // 0xc0deface - config PRNG seed
        $c4 = { b9 79 37 9e }   // 0x9e3779b9 - lowbias32 increment
        $c5 = { 2d 35 eb 7f }   // 0x7feb352d - lowbias32 multiplier
        $c6 = { 8b a6 6c 84 }   // 0x846ca68b - lowbias32 multiplier
        $c7 = { 61 76 c0 2e }   // 0x2ec07661 - stage-3 export hash
    condition:
        filesize < 2MB and 4 of ($c*)
}

rule MagnetWire_loader_pdb
{
    meta:
        description = "Original loader PDB path (BinLoadTester template)"
        date = "2026-10-29"
        severity = "medium"
    strings:
        $pdb = "H:\\window\\tools\\BinLoadTester\\TestExeTemplates\\out\\x64\\create_thread_safe_64.pdb" ascii
    condition:
        $pdb
}

rule MagnetWire_v2_config_memory
{
    meta:
        description = "Decrypted DMV2 configuration in process memory"
        date = "2026-10-29"
        severity = "high"
    strings:
        $marker = { 25 40 29 21 23 21 24 }   // %@)!#!$
        $magic  = "DMV2"
    condition:
        for any i in (1..#marker) : ( $magic at (@marker[i] + 7) )
}
