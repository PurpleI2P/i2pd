/*
* Copyright (c) 2022-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <map>
#include <vector>
#include <string>
#include <memory>
#include "I18N.h"

// German localization file

namespace i2p
{
namespace i18n
{
namespace german // language namespace
{
	// language name in lowercase
	static std::string language = "german";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "In Bau"},
		{"failed", "fehlgeschlagen"},
		{"expiring", "läuft ab"},
		{"established", "hergestellt"},
		{"unknown", "Unbekannt"},
		{"exploratory", "erforschend"},
		{"Purple I2P Webconsole", "Purple I2P-Webkonsole"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b>-Webkonsole"},
		{"Main page", "Startseite"},
		{"Router commands", "Routerbefehle"},
		{"Local Destinations", "Lokale Ziele"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Tunnel"},
		{"Transit Tunnels", "Transittunnel"},
		{"Transports", "Transporte"},
		{"I2P tunnels", "I2P Tunnel"},
		{"SAM sessions", "SAM Sitzungen"},
		{"ERROR", "FEHLER"},
		{"OK", "OK"},
		{"Testing", "Testen"},
		{"Firewalled", "Hinter einer Firewall"},
		{"Unknown", "Unbekannt"},
		{"Proxy", "Proxy"},
		{"Mesh", "Mesh"},
		{"Clock skew", "Zeitabweichung"},
		{"Offline", "Offline"},
		{"Symmetric NAT", "Symmetrisches NAT"},
		{"No Descriptors", "Keine Beschreibungen"},
		{"Uptime", "Laufzeit"},
		{"Network status", "Netzwerkstatus"},
		{"Network status v6", "Netzwerkstatus v6"},
		{"Stopping in", "Stoppt in"},
		{"Family", "Familie"},
		{"Tunnel creation success rate", "Erfolgsrate der Tunnelerstellung"},
		{"Received", "Eingegangen"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Gesendet"},
		{"Transit", "Transit"},
		{"Data path", "Datenpfad"},
		{"Hidden content. Press on text to see.", "Versteckter Inhalt. Klicke hier, um ihn zu sehen."},
		{"Router Ident", "Routeridentität"},
		{"Router Family", "Routerfamilie"},
		{"Router Caps", "Routerattribute"},
		{"Version", "Version"},
		{"Our external address", "Unsere externe Adresse"},
		{"supported", "unterstützt"},
		{"Routers", "Router"},
		{"Floodfills", "Floodfills"},
		{"Client Tunnels", "Clienttunnel"},
		{"Services", "Services"},
		{"Enabled", "Aktiviert"},
		{"Disabled", "Deaktiviert"},
		{"Encrypted B33 address", "Verschlüsselte B33-Adresse"},
		{"Address registration line", "Adressregistrierungszeile"},
		{"Domain", "Domain"},
		{"Generate", "Generieren"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Hinweis:</b> Der resultierende String kann nur für die Registrierung einer 2LD-Domain (beispiel.i2p) benutzt werden. Für die Registrierung von Subdomains kann i2pd-tools verwendet werden."},
		{"Address", "Adresse"},
		{"Type", "Typ"},
		{"EncType", "Verschlüsselungstyp"},
		{"Inbound tunnels", "Eingehende Tunnel"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Ausgehende Tunnel"},
		{"Tags", "Tags"},
		{"Incoming", "Eingehend"},
		{"Outgoing", "Ausgehend"},
		{"Destination", "Ziel"},
		{"Amount", "Anzahl"},
		{"Incoming Tags", "Eingehende Tags"},
		{"Tags sessions", "Tags-Sitzungen"},
		{"Status", "Status"},
		{"Local Destination", "Lokales Ziel"},
		{"Streams", "Streams"},
		{"Close stream", "Stream schließen"},
		{"I2CP session not found", "I2CP-Sitzung nicht gefunden"},
		{"I2CP is not enabled", "I2CP ist nicht aktiviert"},
		{"Invalid", "Ungültig"},
		{"Store type", "Speichertyp"},
		{"Expires", "Ablaufdatum"},
		{"Non Expired Leases", "Nicht abgelaufene Leases"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Enddatum"},
		{"floodfill mode is disabled", "Floodfill Modus ist deaktiviert"},
		{"Queue size", "Größe der Warteschlange"},
		{"Run peer test", "Peer-Test durchführen"},
		{"Reload tunnels configuration", "Tunnel Konfiguration neu laden"},
		{"Decline transit tunnels", "Transittunnel ablehnen"},
		{"Accept transit tunnels", "Transittunnel akzeptieren"},
		{"Cancel graceful shutdown", "Beende das kontrollierte Herunterfahren"},
		{"Start graceful shutdown", "Starte das kontrollierte Herunterfahren"},
		{"Force shutdown", "Herunterfahren erzwingen"},
		{"Reload external CSS styles", "Lade externe CSS-Stile neu"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Hinweis:</b> Alle hier durchgeführten Aktionen sind nicht dauerhaft und ändern die Konfigurationsdateien nicht."},
		{"Logging level", "Protokollierungslevel"},
		{"Transit tunnels limit", "Limit für Transittunnel"},
		{"Change", "Ändern"},
		{"Change language", "Sprache ändern"},
		{"no transit tunnels currently built", "derzeit keine Transittunnel aufgebaut"},
		{"SAM disabled", "SAM deaktiviert"},
		{"no sessions currently running", "Derzeit keine laufenden Sitzungen"},
		{"SAM session not found", "SAM-Sitzung nicht gefunden"},
		{"SAM Session", "SAM-Sitzung"},
		{"Server Tunnels", "Servertunnel"},
		{"Client Forwards", "Client-Weiterleitungen"},
		{"Server Forwards", "Server-Weiterleitungen"},
		{"Unknown page", "Unbekannte Seite"},
		{"Invalid token", "Ungültiger Token"},
		{"SUCCESS", "ERFOLGREICH"},
		{"Stream closed", "Stream geschlossen"},
		{"Stream not found or already was closed", "Stream nicht gefunden oder bereits geschlossen"},
		{"Destination not found", "Ziel nicht gefunden"},
		{"StreamID can't be null", "StreamID kann nicht null sein"},
		{"Return to destination page", "Zurück zur Ziel-Seite"},
		{"You will be redirected in %d seconds", "Du wirst umgeleitet in %d Sekunden"},
		{"Transit tunnels count must not exceed %d", "Die Anzahl der Transittunnel darf nicht über %d gehen"},
		{"Back to commands list", "Zurück zur Befehlsliste"},
		{"Register at reg.i2p", "Auf reg.i2p registrieren"},
		{"Description", "Beschreibung"},
		{"A bit information about service on domain", "Ein paar Informationen über den Service auf der Domain"},
		{"Submit", "Absenden"},
		{"Domain can't end with .b32.i2p", "Domain kann nicht auf .b32.i2p enden"},
		{"Domain must end with .i2p", "Domain muss auf .i2p enden"},
		{"Such destination is not found", "Ein solches Ziel konnte nicht gefunden werden"},
		{"Unknown command", "Unbekannter Befehl"},
		{"Command accepted", "Befehl akzeptiert"},
		{"Proxy error", "Proxy-Fehler"},
		{"Proxy info", "Proxy-Info"},
		{"Proxy error: Host not found", "Proxy-Fehler: Host nicht gefunden"},
		{"Remote host not found in router's addressbook", "Remote-Host nicht im Router-Adressbuch gefunden"},
		{"You may try to find this host on jump services below", "Vielleicht kannst du diesen Host auf einem der nachfolgenden Jump-Services finden"},
		{"Invalid request", "Ungültige Anfrage"},
		{"Proxy unable to parse your request", "Proxy konnte die Anfrage nicht verarbeiten"},
		{"Addresshelper is not supported", "Adresshelfer wird nicht unterstützt"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Host %s ist <font color=red>bereits im Adressbuch des Routers</font>. <b>Vorsicht: Die Quelle dieser URL kann schädlich sein!</b> Klicken Sie hier, um den Datensatz zu aktualisieren: <a href=\"%s%s%s&update=true\">Weiter</a>."},
		{"Addresshelper forced update rejected", "Adresshelfer gezwungene Aktualisierung abgelehnt"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Um den Host <b>%s</b> im Adressbuch des Routers hinzuzufügen, klicken Sie hier: <a href=\"%s%s%s\">Weiter</a>."},
		{"Addresshelper request", "Adresshelfer gefunden"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Host %s wurde vom Helfer zum Adressbuch des Routers hinzugefügt. Klicken Sie hier, um fortzufahren: <a href=\"%s\">Weiter</a>."},
		{"Addresshelper adding", "Adresshelfer hinzufügen"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Host %s ist <font color=red>bereits im Adressbuch des Routers</font>. Klicken Sie hier, um den Eintrag zu aktualisieren: <a href=\"%s%s%s&update=true\">Weiter</a>."},
		{"Addresshelper update", "Adresshelfer aktualisieren"},
		{"Invalid request URI", "Ungültige Anfrage-URI"},
		{"Can't detect destination host from request", "Kann den Ziel-Host von der Anfrage nicht erkennen"},
		{"Outproxy failure", "Outproxy-Fehler"},
		{"Bad outproxy settings", "Ungültige Outproxy-Einstellungen"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Host %s außerhalb des I2P-Netzwerks, aber Outproxy ist nicht aktiviert"},
		{"Unknown outproxy URL", "Unbekannte Outproxy-URL"},
		{"Cannot resolve upstream proxy", "Kann den Upstream-Proxy nicht auflösen"},
		{"Hostname is too long", "Hostname zu lang"},
		{"Cannot connect to upstream SOCKS proxy", "Kann keine Verbindung zum Upstream-SOCKS-Proxy herstellen"},
		{"Cannot negotiate with SOCKS proxy", "Kann nicht mit SOCKS-Proxy verhandeln"},
		{"CONNECT error", "CONNECT-Fehler"},
		{"Failed to connect", "Verbindung konnte nicht hergestellt werden"},
		{"SOCKS proxy error", "SOCKS-Proxy-Fehler"},
		{"Failed to send request to upstream", "Anfrage an den Upstream zu senden ist gescheitert"},
		{"No reply from SOCKS proxy", "Keine Antwort vom SOCKS-Proxy"},
		{"Cannot connect", "Kann nicht verbinden"},
		{"HTTP out proxy not implemented", "HTTP-Outproxy nicht implementiert"},
		{"Cannot connect to upstream HTTP proxy", "Kann nicht zu Upstream-HTTP-Proxy verbinden"},
		{"Host is down", "Host ist offline"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Konnte keine Verbindung zum angefragten Host aufbauen, vielleicht ist er offline. Versuche es später noch mal."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d Tag", "%d Tage"}},
		{"%d hours", {"%d Stunde", "%d Stunden"}},
		{"%d minutes", {"%d Minute", "%d Minuten"}},
		{"%d seconds", {"%d Sekunde", "%d Sekunden"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
