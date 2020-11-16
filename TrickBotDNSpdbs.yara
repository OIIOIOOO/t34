rule anchor_dns_pdbs {
    meta:
        description = "Rule to detect AnchorDNS samples based off partial PDB
paths" 
        author = "NCSC"
        hash1 = "f0e575475f33600aede6a1b9a5c14f671cb93b7b"
        hash2 = "1304372bd4cdd877778621aea715f45face93d68"
        hash3 = "e5dc7c8bfa285b61dda1618f0ade9c256be75d1a"
        hash4 = "f96613ac6687f5dbbed13c727fa5d427e94d6128"
        hash5 = "46750d34a3a11dd16727dc622d127717beda4fa2" 
    strings:
        $ = ":\\MyProjects\\secondWork\\Anchor\\"
        $ = ":\\simsim\\anchorDNS"
        $ = ":\\[JOB]\\Anchor\\"
        $ = ":\\Anchor\\Win32\\Release\\Anchor_"
        $ = ":\\Users\\ProFi\\Desktop\\data\\Win32\\anchor"
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}