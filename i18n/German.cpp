/*
* Copyright (c) 2022, The PurpleI2P Project
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
		{"KiB", "KiB"},
		{"MiB", "MiB"},
		{"GiB", "GiB"},
		{"building", "In Bau"},
		{"failed", "fehlgeschlagen"},
		{"expiring", "läuft ab in"},
		{"established", "hergestellt"},
		{"unknown", "Unbekannt"},
		{"exploratory", "erforschende"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> Webkonsole"},
		{"Main page", "Startseite"},
		{"Router commands", "Router Befehle"},
		{"Local Destinations", "Lokale Destination"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Tunnel"},
		{"Transit Tunnels", "Transittunnel"},
		{"Transports", "Transporte"},
		{"I2P tunnels", "I2P Tunnel"},
		{"SAM sessions", "SAM Sitzungen"},
		{"ERROR", "FEHLER"},
		{"OK", "OK"},
		{"Testing", "Testen"},
		{"Firewalled", "Hinter eine Firewall"},
		{"Unknown", "Unbekannt"},
		{"Proxy", "Proxy"},
		{"Mesh", "Mesh"},
		{"Error", "Fehler"},
		{"Clock skew", "Zeitabweichung"},
		{"Offline", "Offline"},
		{"Symmetric NAT", "Symmetrisches NAT"},
		{"Uptime", "Laufzeit"},
		{"Network status", "Netzwerkstatus"},
		{"Network status v6", "Netzwerkstatus v6"},
		{"Stopping in", "Stoppt in"},
		{"Family", "Familie"},
		{"Tunnel creation success rate", "Erfolgsrate der Tunnelerstellung"},
		{"Received", "Eingegangen"},
		{"KiB/s", "KiB/s"},
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
		{"Client Tunnels", "Klienttunnel"},
		{"Services", "Services"},
		{"Enabled", "Aktiviert"},
		{"Disabled", "Deaktiviert"},
		{"Encrypted B33 address", "Verschlüsselte B33 Adresse"},
		{"Address registration line", "Adresseregistrierungszeile"},
		{"Domain", "Domain"},
		{"Generate", "Generieren"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Hinweis:</b> Der resultierende String kann nur für die Registrierung einer 2LD Domain (beispiel.i2p) benutzt werden. Für die Registrierung von Subdomains kann i2pd-tools verwendet werden."},
		{"Address", "Adresse"},
		{"Type", "Typ"},
		{"EncType", "Verschlüsselungstyp"},
		{"Inbound tunnels", "Eingehende Tunnel"},
		{"ms", "ms"},
		{"Outbound tunnels", "Ausgehende Tunnel"},
		{"Tags", "Tags"},
		{"Incoming", "Eingehend"},
		{"Outgoing", "Ausgehend"},
		{"Destination", "Destination"},
		{"Amount", "Anzahl"},
		{"Incoming Tags", "Eingehende Tags"},
		{"Tags sessions", "Tags Sitzungen"},
		{"Status", "Status"},
		{"Local Destination", "Lokale Destination"},
		{"Streams", "Streams"},
		{"Close stream", "Stream schließen"},
		{"I2CP session not found", "I2CP Sitzung nicht gefunden"},
		{"I2CP is not enabled", "I2CP ist nicht aktiviert"},
		{"Invalid", "Ungültig"},
		{"Store type", "Speichertyp"},
		{"Expires", "Ablaufdatum"},
		{"Non Expired Leases", "Nicht abgelaufene Leases"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Enddatum"},
		{"not floodfill", "kein Floodfill"},
		{"Queue size", "Warteschlangengröße"},
		{"Run peer test", "Peer-Test ausführen"},
		{"Decline transit tunnels", "Transittunnel ablehnen"},
		{"Accept transit tunnels", "Transittunnel akzeptieren"},
		{"Cancel graceful shutdown", "Beende das kontrollierte herunterfahren"},
		{"Start graceful shutdown", "Starte das kontrollierte Herunterfahren"},
		{"Force shutdown", "Herunterfahren erzwingen"},
		{"Reload external CSS styles", "Lade externe CSS-Styles neu"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Hinweis:</b> Alle hier durchgeführten Aktionen sind nicht dauerhaft und ändern die Konfigurationsdateien nicht."},
		{"Logging level", "Protokollierungslevel"},
		{"Transit tunnels limit", "Limit für Transittunnel"},
		{"Change", "Verändern"},
		{"Change language", "Sprache ändern"},
		{"no transit tunnels currently built", "derzeit keine Transittunnel aufgebaut"},
		{"SAM disabled", "SAM deaktiviert"},
		{"no sessions currently running", "Derzeit keine laufenden Sitzungen"},
		{"SAM session not found", "SAM Sitzung nicht gefunden"},
		{"SAM Session", "SAM Sitzung"},
		{"Server Tunnels", "Servertunnel"},
		{"Client Forwards", "Klient-Weiterleitungen"},
		{"Server Forwards", "Server-Weiterleitungen"},
		{"Unknown page", "Unbekannte Seite"},
		{"Invalid token", "Ungültiger Token"},
		{"SUCCESS", "ERFOLGREICH"},
		{"Stream closed", "Stream geschlossen"},
		{"Stream not found or already was closed", "Stream nicht gefunden oder bereits geschlossen"},
		{"Destination not found", "Destination nicht gefunden"},
		{"StreamID can't be null", "StreamID kann nicht null sein"},
		{"Return to destination page", "Zurück zur Destination-Seite"},
		{"You will be redirected in 5 seconds", "Du wirst in 5 Sekunden weitergeleitet"},
		{"Transit tunnels count must not exceed 65535", "Es darf maximal 65535 Transittunnel geben"},
		{"Back to commands list", "Zurück zur Kommandoliste"},
		{"Register at reg.i2p", "Auf reg.i2p registrieren"},
		{"Description", "Beschreibung"},
		{"A bit information about service on domain", "Ein bisschen Informationen über den Service auf der Domain"},
		{"Submit", "Einreichen"},
		{"Domain can't end with .b32.i2p", "Domain kann nicht mit .b32.i2p enden"},
		{"Domain must end with .i2p", "Domain muss mit .i2p enden"},
		{"Such destination is not found", "Eine solche Destination konnte nicht gefunden werden"},
		{"Unknown command", "Unbekannter Befehl"},
		{"Command accepted", "Befehl akzeptiert"},
		{"Proxy error", "Proxy-Fehler"},
		{"Proxy info", "Proxy-Info"},
		{"Proxy error: Host not found", "Proxy-Fehler: Host nicht gefunden"},
		{"Remote host not found in router's addressbook", "Remote-Host nicht im Router Adressbuch gefunden"},
		{"You may try to find this host on jump services below", "Vielleicht kannst du diesen Host auf einen der Jump-Services unten finden"},
		{"Invalid request", "Ungültige Anfrage"},
		{"Proxy unable to parse your request", "Proxy konnte die Anfrage nicht interpretieren"},
		{"addresshelper is not supported", "addresshelper wird nicht unterstützt"},
		{"Host", "Host"},
		{"added to router's addressbook from helper", "vom Helfer zum Router Adressbuch hinzugefügt"},
		{"Click here to proceed:", "Klicke hier um fortzufahren:"},
		{"Continue", "Fortsetzen"},
		{"Addresshelper found", "Adresshelfer gefunden"},
		{"already in router's addressbook", "bereits im Adressbuch des Routers"},
		{"Click here to update record:", "Klicke hier, um den Eintrag zu aktualisieren:"},
		{"invalid request uri", "ungültige Anfrage-URI"},
		{"Can't detect destination host from request", "Kann Anhand der Anfrage den Destination-Host nicht erkennen"},
		{"Outproxy failure", "Outproxy-Fehler"},
		{"bad outproxy settings", "ungültige Outproxy-Einstellungen"},
		{"not inside I2P network, but outproxy is not enabled", "nicht innerhalb des I2P-Netzwerks, aber Outproxy ist nicht aktiviert"},
		{"unknown outproxy url", "unbekannte Outproxy-URL"},
		{"cannot resolve upstream proxy", "kann den Upstream-Proxy nicht auflösen"},
		{"hostname too long", "Hostname zu lang"},
		{"cannot connect to upstream socks proxy", "Kann keine Verbindung zum Upstream-Socks-Proxy herstellen"},
		{"Cannot negotiate with socks proxy", "Kann nicht mit Socks-Proxy verhandeln"},
		{"CONNECT error", "CONNECT-Fehler"},
		{"Failed to Connect", "Verbindung konnte nicht hergestellt werden"},
		{"socks proxy error", "Socks-Proxy-Fehler"},
		{"failed to send request to upstream", "Anfrage an den Upstream zu senden ist gescheitert"},
		{"No Reply From socks proxy", "Keine Antwort vom Socks-Proxy"},
		{"cannot connect", "kann nicht verbinden"},
		{"http out proxy not implemented", "HTTP-Outproxy nicht implementiert"},
		{"cannot connect to upstream http proxy", "Kann nicht zu Upstream-HTTP-Proxy verbinden"},
		{"Host is down", "Host ist offline"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Konnte keine Verbindung zum angefragten Host aufbaunen, vielleicht ist es offline. Versuche es später noch einmal."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days", {"Tag", "Tage"}},
		{"hours", {"Stunde", "Stunden"}},
		{"minutes", {"Minute", "Minuten"}},
		{"seconds", {"Sekunde", "Sekunden"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
