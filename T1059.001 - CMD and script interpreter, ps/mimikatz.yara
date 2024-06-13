title:  Invoke-Mimikatz PowerShell Script
id: 189e3b02-82b2-4b90-9662-411eb64486d4
status: test
description: Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.
references:
    - https://www.elastic.co/guide/en/security/current/potential-invoke-mimikatz-powershell-script.html#potential-invoke-mimikatz-powershell-script
    - https://detection.fyi/sigmahq/sigma/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz/
    - https://atomicredteam.io/execution/T1059.001/
    - https://github.com/ParrotSec/mimikatz
author: Hyun Woo Kim
date: 2024/06/13
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_sekurlsa:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::tickets /export'
            - 'sekurlsa::pth'
    selection_kerberos:
        CommandLine|contains:
            - 'kerberos::list'
            - 'kerberos::ptt'
            - 'kerberos::golden'
    selection_crypto:
        CommandLine|contains:
            - 'crypto::capi'
            - 'crypto::cng'
            - 'crypto::certificates'
            - 'crypto::keys'
    selection_vault_lsadump:
        CommandLine|contains:
            - 'vault::cred'
            - 'vault::list'
            - 'token::elevate'
            - 'lsadump::sam'
            - 'lsadump::secrets'
            - 'lsadump::cache'
            - 'token::revert'
            - 'lsadump:dcsync'
    condition: 1 of selection