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
  - <img width="1920" height="1080" alt="wazuh_user_access" src="https://github.com/user-attachments/assets/3805c9e7-2d0c-4d0b-a08e-5a369ca26fc6" />

- Domain Controller successfully registered as an active Wazuh agent
  - <img width="1918" height="748" alt="wazuh_successfully_added_server2019" src="https://github.com/user-attachments/assets/d56576d6-6b07-49c7-b4c2-05597f4b93b9" />

- Sysmon installed
  - <img width="851" height="580" alt="wazuh_sysmon_installation" src="https://github.com/user-attachments/assets/9b922085-f3fc-4ab3-8294-53bd10254655" />

- Required Windows audit policies enabled
  - <img width="951" height="386" alt="wazuh_enabling_audit_policies_explicitly" src="https://github.com/user-attachments/assets/903cebc3-0ff4-4a34-bd3d-63ac58c3a09b" />


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


<img width="1920" height="1080" alt="wazuh_rules_kerberoasting" src="https://github.com/user-attachments/assets/1c3fafcd-3856-40ec-8488-c3e52386b78f" />



## Attack

```bash
impacket-GetUserSPNs corp.local/sony \
-dc-ip 192.168.56.104 \
-request
```

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_kerberoasting" src="https://github.com/user-attachments/assets/2973442e-fbb7-4c44-86f0-f646e53cb00d" />




## Detection

The custom rule triggered successfully.

- Rule ID: **100010**
- MITRE: **T1558.003**
- Severity: Level 12

Evidence:

- <img width="1920" height="1080" alt="wazuh_attack_kerberoasting_captured" src="https://github.com/user-attachments/assets/ece1bdbc-d4e5-48b6-b1b5-be7d81d02a1b" />

- <img width="1920" height="1080" alt="wazuh_attack_kerberoasting_queried" src="https://github.com/user-attachments/assets/17ac54ed-f622-4acf-b1af-de2557b6ffd1" />


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


<img width="1920" height="1080" alt="wazuh_rules_as_rep" src="https://github.com/user-attachments/assets/2a3ce4a2-1136-47b0-9885-9c3bf8aa1a1f" />



## Attack

```bash
impacket-GetNPUsers corp.local/ \
-usersfile <(echo sony) \
-dc-ip 192.168.56.104 \
-no-pass
```

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_as_rep" src="https://github.com/user-attachments/assets/e36d2196-1776-4228-9bfd-da70f3f57072" />



## Detection

The alert fired successfully.

- Rule ID: **100011**
- MITRE: **T1558.004**
- Severity: Level 12

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_as_rep_queried" src="https://github.com/user-attachments/assets/256b98c4-f36a-4656-baf0-3e9df82ed013" />



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

- <img width="996" height="730" alt="wazuh_attack_remote_exec_captured_default_defender" src="https://github.com/user-attachments/assets/5b738468-7215-4e68-87ab-b3e350b09202" />

- <img width="1920" height="1080" alt="wazuh_attack_remote_exec_error" src="https://github.com/user-attachments/assets/78cbd13f-0689-4376-a37d-3efaf9776dbe" />



### Lab Adjustment

Real-time protection was temporarily disabled:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Evidence:


<img width="600" height="117" alt="wazuh_disabling_realTimeMonitoring" src="https://github.com/user-attachments/assets/a58bd602-79cc-442e-a4f7-b1ce5213937a" />


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


<img width="1920" height="1080" alt="wazuh_attack_remote_exec_default_rule_alert" src="https://github.com/user-attachments/assets/165616d2-b5ae-4f20-a506-230217f80e32" />



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


<img width="861" height="255" alt="wazuh_rules_admin_previlege" src="https://github.com/user-attachments/assets/02bfa01a-7458-4bdb-9c71-8310c34cefed" />


## Attack

```powershell
Remove-ADGroupMember -Identity "Domain Admins" `
-Members svc_sql `
-Confirm:$false

Add-ADGroupMember -Identity "Domain Admins" `
-Members svc_sql
```

Evidence:


<img width="847" height="407" alt="wazuh_removed_svc_sql_admin_access_added_again" src="https://github.com/user-attachments/assets/d95d68fe-e074-4ba9-847a-56da628fc265" />


## Detection

The alert fired successfully.

- Rule ID: **100013**
- Severity: Level 14
- MITRE: **T1098.007**

Evidence:


<img width="1920" height="1080" alt="wazuh_attack_admin_previlege_alert" src="https://github.com/user-attachments/assets/e4f5b558-7b1f-4819-861d-f3f50d1d5f0e" />

---

# Vulnerability Detection

Wazuh's Vulnerability Detection module also identified a large number of vulnerabilities affecting the Windows Server 2019 Evaluation installation.

| Severity | Count |
|-----------|------:|
| Critical | 23 |
| High | 1,164 |
| Medium | 489 |

Evidence:

<img width="1920" height="1080" alt="wazuh_dashboard_alerts" src="https://github.com/user-attachments/assets/ed18acc3-55a6-4624-a40a-63576e8b418a" />


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

