## Przypisanie reguł do reakcji

| Reguła | Co oznacza | Active response |
| :-- | :-- | :-- |
| `100856` | 10 nieudanych logowań z jednego IP w 60 s | `netsh-drop` |
| `100900` | wiele technik initial access z jednego źródła | `isolate-host` |
| `100901` | DCSync po użyciu poświadczeń | `isolate-host` |
| `100902` | kilka wskaźników Kerberoasting z jednego źródła | `isolate-host` |
| `100903` | Pass-the-Hash / Pass-the-Ticket | `isolate-host` |
| `100904` | potwierdzone aktywne C2 | `isolate-host` |
| `100750` | Cobalt Strike indicator | `isolate-host` |
| `100751` | Sliver/Havoc/BRC4 indicator | `isolate-host` |

To przypisanie jest rozsądne, bo `100856` to typowy trigger do blokady źródłowego IP, a reguły `100900-100904`, `100750`, `100751` sugerują już realny incydent, więc lepiej odciąć cały endpoint niż tylko IP atakującego.[^4][^2][^3]

## Konfiguracja ossec.conf

Poniżej masz gotowy wariant dla Windows endpointów. Zakładam, że:

- `netsh-drop` jest używany do blokady IP na Windows,
- `isolate-host.cmd` to Twój własny skrypt/EXE izolacji hosta, (CMD - wrapper problematycznych PS1)
- oba pliki znajdują się na agencie w `C:\Program Files (x86)\ossec-agent\active-response\bin\`.[^3]

```xml
<ossec_config>

  <command>
    <name>netsh-drop</name>
    <executable>netsh-drop.exe</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>isolate-host</name>
    <executable>isolate-host.cmd</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>netsh-drop</command>
    <location>local</location>
    <rules_id>100856</rules_id>
    <timeout>15</timeout>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>isolate-host</command>
    <location>local</location>
    <rules_id>100900,100901,100902,100903,100904,100750,100751</rules_id>
    <timeout>60</timeout>
  </active-response>

</ossec_config>
```


## Co powinien robić skrypt izolacji

Wariant dla Windows najlepiej zrobić jako `isolate-host.exe` albo skrypt uruchamiany przez launcher, bo Wazuh na Windows wspiera zarówno EXE, jak i uruchamianie własnych skryptów przez launcher/pyinstaller.[^3]
Sam skrypt izolacji może:

- dodać reguły Windows Firewall,
- odciąć ruch wychodzący i przychodzący,
- opcjonalnie odłączyć interfejs sieciowy,
- uruchomić akcję Microsoft Defender for Endpoint, jeśli masz integrację z MDE.[^5][^4]


## Praktyczna uwaga

Dla `100856` blokada IP jest dobra, ale dla `100900-100904` oraz `100750-100751` lepiej traktować host jako potencjalnie kompromitowany i przejść do izolacji, bo to są już wskaźniki ruchu lateralnego, C2 albo eskalacji.[^2]
<span style="display:none">[^10][^11][^12][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://www.reddit.com/r/Wazuh/comments/1hdd5e9/wazuh_active_response/

[^2]: local_rules.xml

[^3]: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html

[^4]: https://learn.microsoft.com/pl-pl/microsoft-365/security/defender-endpoint/respond-machine-alerts?view=o365-worldwide

[^5]: https://learn.microsoft.com/pl-pl/defender-endpoint/respond-machine-alerts

[^6]: https://blog.askomputer.pl/jak-zintegrowac-wazuh-z-windows-defender-i-virustotal-krok‑po‑kroku/

[^7]: https://www.reddit.com/r/Wazuh/comments/1ntr9jh/trigger_wazuh_activeresponse_script_remotely/

[^8]: https://www.youtube.com/watch?v=sbRuU3P8wxI

[^9]: https://www.reddit.com/r/Wazuh/comments/1obla1a/wazuh_active_response_ideas/

[^10]: https://www.reddit.com/r/Wazuh/comments/1fkivif/windows_logon_sucess_exclusion_in_wazuh/

[^11]: https://learn.microsoft.com/pl-pl/defender-endpoint/live-response

[^12]: https://www.gov.pl/attachment/e610f87b-df74-466b-9964-e03bdfada5e4

