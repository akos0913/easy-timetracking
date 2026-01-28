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

Siehe `schema.sql` für die Tabellen `users` und `sessions`.

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
