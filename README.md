# Blue Team Detection Lab – Part 2 of the AD Penetration Testing Lab

## Project Overview

This project extends the **Internal Active Directory Penetration Testing Lab** by adding a detection layer using Wazuh.

After compromising the Active Directory environment during the penetration test, the same attack techniques were re-executed against a live Wazuh deployment to verify whether they could be detected. Where the default Wazuh ruleset lacked coverage, custom detection rules were developed.

The following attack techniques were tested:

1. Kerberoasting
2. AS-REP Roasting
3. Remote Service Execution (PsExec-style lateral movement)
4. Domain Admin group privilege escalation

**Result:** All four attack techniques were successfully detected using a combination of custom Wazuh rules and built-in detections.

---

# Environment

The same infrastructure from the penetration testing lab was reused.

| Machine | Role | IP Address |
|---------|------|------------|
| Kali Linux | Attacker + Wazuh Manager/Indexer/Dashboard | 192.168.56.101 |
| Windows Server 2019 | Domain Controller + Wazuh Agent + Sysmon | 192.168.56.104 |

> **Note**
>
> Running the Wazuh Manager on the attacker machine is purely a lab simplification. In production, the SIEM infrastructure should always be deployed on separate hardened systems.

---

# Methodology

1. Install Wazuh (all-in-one) on Kali Linux.
2. Register the Windows Server 2019 Domain Controller as a monitored endpoint.
3. Install Sysmon.
4. Enable the required Windows Audit Policies.
5. Re-execute each attack from the penetration test.
6. Verify detections inside Wazuh.
7. Develop custom detection rules where necessary.
8. Map detections to the MITRE ATT&CK framework.

---

# Setup Evidence

- Wazuh all-in-one successfully installed on Kali
  - <img width="1920" height="1080" alt="wazuh_user_access" src="https://github.com/user-attachments/assets/ed947c13-0049-4b92-83f6-9656b7a4400a" />


- Domain Controller successfully registered as an active Wazuh agent
  - <img width="1918" height="748" alt="wazuh_successfully_added_server2019" src="https://github.com/user-attachments/assets/480923ed-b255-4879-95bc-817407d803f6" />


- Sysmon installed
  - <img width="851" height="580" alt="wazuh_sysmon_installation" src="https://github.com/user-attachments/assets/f14aa4b2-74d6-47cc-b900-b5b74650d021" />


- Required Windows audit policies enabled
  - <img width="951" height="386" alt="wazuh_enabling_audit_policies_explicitly" src="https://github.com/user-attachments/assets/48c7d2e5-2363-477e-9aed-7a1e41086dad" />



---

# Detection Summary

| Detection | Rule Type | Rule ID | MITRE ATT&CK | Status |
|-----------|-----------|---------|--------------|--------|
| Kerberoasting | Custom | 100010 | T1558.003 | ✅ |
| AS-REP Roasting | Custom | 100011 | T1558.004 | ✅ |
| Remote Service Execution | Default Wazuh | 92650 | T1021.002 / T1569.002 | ✅ |
| Domain Admin Group Addition | Custom | 100013 | T1098.007 | ✅ |

---

# Detection 1 — Kerberoasting

## Custom Rule

```xml
<group name="windows,attack,">
  <rule id="100010" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>
      Possible Kerberoasting: RC4 service ticket requested
    </description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

Rule screenshot:


<img width="1920" height="1080" alt="wazuh_rules_kerberoasting" src="https://github.com/user-attachments/assets/4b1521ed-d591-43fa-a11f-3cef125e0126" />




## Attack

```bash
impacket-GetUserSPNs corp.local/sony \
-dc-ip 192.168.56.104 \
-request
```

Evidence:

<img width="1920" height="1080" alt="wazuh_attack_kerberoasting" src="https://github.com/user-attachments/assets/9a83d9da-f322-44a5-a4ec-96c98bc06dd3" />





## Detection

The custom rule triggered successfully.

- Rule ID: **100010**
- MITRE: **T1558.003**
- Severity: Level 12

Evidence:

- <img width="1920" height="1080" alt="wazuh_attack_kerberoasting_captured" src="https://github.com/user-attachments/assets/51ae26f9-1a79-4ff0-a45e-57fd28693cce" />


- <img width="1920" height="1080" alt="wazuh_attack_kerberoasting_queried" src="https://github.com/user-attachments/assets/36686ffa-9ed7-43d8-b07b-dfe08b3a7ccf" />



---

# Detection 2 — AS-REP Roasting

## Custom Rule

```xml
<rule id="100011" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4768$</field>
  <field name="win.eventdata.preAuthType">0</field>
  <description>
    Possible AS-REP Roasting
  </description>
  <mitre>
    <id>T1558.004</id>
  </mitre>
</rule>
```

Rule screenshot:


<img width="1920" height="1080" alt="wazuh_rules_as_rep" src="https://github.com/user-attachments/assets/4c938f84-daa9-447d-8020-92dbd00d8dae" />




## Attack

```bash
impacket-GetNPUsers corp.local/ \
-usersfile <(echo sony) \
-dc-ip 192.168.56.104 \
-no-pass
```

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_as_rep" src="https://github.com/user-attachments/assets/3bfdfe0b-17d8-4466-9a0e-846239a646b8" />




## Detection

The alert fired successfully.

- Rule ID: **100011**
- MITRE: **T1558.004**
- Severity: Level 12

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_as_rep_queried" src="https://github.com/user-attachments/assets/761037fc-7475-4703-aec2-c4ae545575b4" />




---

# Detection 3 — Remote Service Execution (PsExec)

Although a custom rule (100012) was developed, Wazuh's default rule **92650** already detected this activity accurately.

## Attack

```bash
psexec.py corp.local/svc_sql@192.168.56.104
```

### First Attempt

Windows Defender intercepted the dropped payload before Wazuh could detect the activity.

Detected as:

```
VirTool:Win32/RemoteExec!pz
```

Evidence:

- <img width="996" height="730" alt="wazuh_attack_remote_exec_captured_default_defender" src="https://github.com/user-attachments/assets/693b436b-c9f7-4f15-8b12-18a7e3bf8184" />


- <img width="1920" height="1080" alt="wazuh_attack_remote_exec_error" src="https://github.com/user-attachments/assets/14bd4d95-15a2-4459-a56b-5835a663f893" />




### Lab Adjustment

Real-time protection was temporarily disabled:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Evidence:


<img width="600" height="117" alt="wazuh_disabling_realTimeMonitoring" src="https://github.com/user-attachments/assets/5d6aae99-e641-439d-966a-20dbce33d749" />



This was performed **only** for detection validation within the lab.

## Detection

The second execution succeeded.

Wazuh's default Rule **92650** generated seven alerts identifying:

- Random service creation
- Executable dropped into `%systemroot%`

MITRE Mapping:

- T1021.002
- T1569.002

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_remote_exec_default_rule_alert" src="https://github.com/user-attachments/assets/33c388ff-1078-479b-8b3d-2502075c160e" />




---

# Detection 4 — Domain Admin Group Addition

## Custom Rule

```xml
<group name="windows,attack,">

<rule id="100013" level="14">

  <if_group>windows</if_group>

  <field name="win.system.eventID">^4728$</field>

  <field name="win.eventdata.targetSid" type="pcre2">-512$</field>

  <description>
    Critical: Account added to Domain Admins group
  </description>

  <mitre>
    <id>T1098.007</id>
  </mitre>

</rule>

</group>
```

Rule screenshot:


<img width="861" height="255" alt="wazuh_rules_admin_previlege" src="https://github.com/user-attachments/assets/f3dd0762-7123-4127-8f50-f7309f94a77f" />



## Attack

```powershell
Remove-ADGroupMember -Identity "Domain Admins" `
-Members svc_sql `
-Confirm:$false

Add-ADGroupMember -Identity "Domain Admins" `
-Members svc_sql
```

Evidence:


<img width="847" height="407" alt="wazuh_removed_svc_sql_admin_access_added_again" src="https://github.com/user-attachments/assets/2c2b1e5e-42ef-42c9-aa7d-576c9157300e" />



## Detection

The alert fired successfully.

- Rule ID: **100013**
- Severity: Level 14
- MITRE: **T1098.007**

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_admin_previlege_alert" src="https://github.com/user-attachments/assets/54d6c494-b2e0-4750-8462-138a0ade5f30" />


---

# Vulnerability Detection

Wazuh's Vulnerability Detection module also identified a large number of vulnerabilities affecting the Windows Server 2019 Evaluation installation.

| Severity | Count |
|-----------|------:|
| Critical | 23 |
| High | 1,164 |
| Medium | 489 |

Evidence:

<img width="1920" height="1080" alt="wazuh_dashboard_alerts" src="https://github.com/user-attachments/assets/141ac8f5-2e19-40a2-a77d-9f6625bdd0d2" />



Although not directly related to the attack simulations, these findings reinforce that the environment presents a significant attack surface due to missing security updates.

---

# Conclusion

This project demonstrates the complete defensive validation cycle following an Active Directory penetration test.

All four attack techniques were successfully detected using either:

- Custom Wazuh detection rules, or
- Wazuh's default ruleset.

Each detection was validated through:

- Re-execution of the attack
- Successful alert generation
- MITRE ATT&CK mapping
