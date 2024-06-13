title: Powershell Execute Batch Script
id: b5522a23-82da-44e5-9c8b-e10ed8955f88
status: test
description: Blackbasta is known to check for prefernce of hard-coded mutex and then later use vssadmin to delete shadow copies to inhibit recovery
references:
    - https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergenceauthor
author: Hyun Woo Kim
date: 2024/06/13
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_volume_delete:
        Image|endswith: vssadmin.exe
    selection_volume_delete_flag:
        CommandLine|contains:
            - '/all'
            - '/quiet'
            - 'delete shadows'
    condition: all of selection_*
falsepositives:
    - Legitimate administration script
level: medium
