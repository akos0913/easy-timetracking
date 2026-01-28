# Easy Time Tracking

Diese Beispielanwendung liefert eine einfache, aber technisch sinnvolle Zeiterfassung mit:

- automatischer Erkennung von Geräten im WLAN (ARP-Scan),
- manueller Start/Stop-Erfassung,
- Tagesansicht der Sessions inkl. Notizen,
- LDAP-Login zur Zuordnung von Mitarbeitern.

## Technik-Stack

- **Backend:** FastAPI
- **Datenbank:** MySQL
- **Frontend:** HTML/CSS + Alpine.js + TailwindCSS (CDN)

## Datenmodell

Siehe `schema.sql` für die Tabellen `users` und `sessions` (inkl. `source` und `is_active`).

## Lokales Setup

1. Datenbank anlegen und Schema importieren.
2. Umgebung konfigurieren:

```bash
export DB_HOST=localhost
export DB_USER=timetracker
export DB_PASSWORD=timetracker
export DB_NAME=timetracking
```

3. LDAP konfigurieren:

```bash
export LDAP_SERVER=ldap://ldap.example.local
export LDAP_BASE_DN=dc=example,dc=local
export LDAP_USER_ATTRIBUTE=uid
export LDAP_USER_DN_TEMPLATE="uid={username},ou=people,dc=example,dc=local"
export LDAP_UPN_SUFFIX=example.local
export LDAP_AUTHENTICATION=SIMPLE
export LDAP_BIND_DN=cn=readonly,dc=example,dc=local
export LDAP_BIND_PASSWORD=secret
export SESSION_SECRET=change-me
```

4. Abhängigkeiten installieren:

```bash
pip install -r requirements.txt
```

5. Server starten:

```bash
uvicorn app:app --reload
```

## Auto-Tracking

Die Auto-Tracking-Logik läuft als Hintergrund-Thread und führt regelmäßig `arp-scan --localnet` aus. Wird eine bekannte MAC-Adresse erkannt, startet das System automatisch eine Session. Bei längerer Abwesenheit (Timeout) wird die Session beendet. Falls `arp-scan` nicht installiert ist, bleibt die Funktion deaktiviert und es funktioniert nur die manuelle Erfassung.

## Migration (bestehende Datenbanken)

Führe diese SQL-Snippets aus, um `source`, `is_active` und den Index nachzurüsten, ohne Fehler zu werfen, falls sie schon existieren:

```sql
-- Add sessions.source column if missing
SET @has_source := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sessions'
    AND COLUMN_NAME = 'source'
);
SET @sql := IF(
  @has_source = 0,
  'ALTER TABLE sessions ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT ''manual''',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add users.is_active column if missing
SET @has_active := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'is_active'
);
SET @sql := IF(
  @has_active = 0,
  'ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add composite index if missing
SET @has_index := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sessions'
    AND INDEX_NAME = 'idx_sessions_user_start'
);
SET @sql := IF(
  @has_index = 0,
  'ALTER TABLE sessions ADD INDEX idx_sessions_user_start (user_id, start_time)',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
```

## Neue Umgebungsvariablen

Zusätzlich zu den bestehenden Variablen werden folgende Optionen unterstützt:

```bash
# Session-Cookies
export SESSION_MAX_AGE=43200        # Sekunden, z.B. 12h
export SESSION_SAMESITE=lax         # lax|strict|none
export SESSION_HTTPS_ONLY=false     # true/false

# LDAP
export LDAP_STARTTLS=false          # StartTLS erzwingen
export LDAP_USE_SSL=false           # SSL erzwingen (oder LDAP_SERVER=ldaps://...)
export LDAP_ADMIN_GROUP_DN=         # LDAP-Gruppe für Admins (DN)
```
