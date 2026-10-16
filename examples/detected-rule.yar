import "hash"

rule Forge_1006af1e {
    meta:
        author = "binary-forge automated triage"
        description = "auto-generated from triage verdict: likely-malicious"
        sample_sha256 = "1006af1e1d35e9cf80484bc760b5d3514a87206b93bd0abbccf92ba9bdac8b99"
        source_file = "fixture.exe"
    strings:
        $s1 = "powershell -enc" // ps-encoded
        $s2 = "CurrentVersion\\Run" // persistence
        $s3 = "powershell" // shell
        $s4 = "http://c2.example.invalid/payload2.bin" // net-url
        $s5 = "VirtualAlloc" // injection
    condition:
        filesize < 50MB and ((hash.sha256(0, filesize) == "1006af1e1d35e9cf80484bc760b5d3514a87206b93bd0abbccf92ba9bdac8b99") or 3 of ($s*))
}
