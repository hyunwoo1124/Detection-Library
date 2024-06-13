title: Takeown Icacls Attrib file mod detected
id: c59a3258-cbc7-4061-a116-bc4f9369e8b2
status: test
description: Detects modified file or directory permission using takeown.exe, cacls.exe, attrib.exe
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility
author: Hyun Woo Kim
date: 2024/06/04
tags:
    - attack.t1222.001
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
    service: security
detection:
    selection_image:
        Image|contains:
            - takeown.exe
            - icacls.exe
            - attrib.exe
    selection_cmdl:
        CommandLine|contains:
            - /f            #takeown.exe
            - /r
            - /grant        #icacls.exe
            - +h
            - /restore
    filter1:
        CommandLine|contains:
            - \SAP
    filter2:
        SourceImage|contains:
            - 'Jabra'
            - 'smartstandbycomponent'
            - '\common files\adobe'
            - '\code.exe'
            - 'codesetup'
            - 'Lenovo Group'
            - 'aws replication agent'
            - '\zebra'
            - '\draw.io'
            - '\sgx_pxw'
            - '\adobe\adobe *'
    filter3:
        CommandLine|contains:
            - '\Lenovo'
            - '\Hive Streaming'
            - 'splunkuniversal'
            - '\barista'
            - '\Mandatory_Profile'
            - '\Merck_QChecker'
            - '\IntelSGXPSW'
            - '\Program Files\PIPC'
            - '\Program Files (x86)\PIPC'
            - '\AnypointStudio'
    condition: (all of selection*) and not (filter1 or filter2 or filter3)
falsepositives:
    - Unknown
level: critical
