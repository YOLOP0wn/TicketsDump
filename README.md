# TicketsDump
Minimal Rubeus implementation, supporting tgtdeleg with impersonation [see Rubeus PR](https://github.com/GhostPack/Rubeus/pull/197)

## Usage

    c:\Temp>TicketsDump.exe --help

    list - list tickets (triage)
    get /id:0x111 - dump ticket with id
    ask [/pid:111] - ask TGT using current/pid token impersonated user context (SSPI)

    Steal token of process with pid 4542, duplicate and impersonate it, then use tgtdeleg to ask a TGT 
    c:\Temp>TicketsDump.exe ask /pid:4542
