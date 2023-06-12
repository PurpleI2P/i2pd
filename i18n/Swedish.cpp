/*
* Copyright (c) 2023, The PurpleI2P Project
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

// Swedish localization file

namespace i2p
{
namespace i18n
{
namespace swedish // language namespace
{
	// language name in lowercase
	static std::string language = "swedish";

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
		{"building", "bygger"},
		{"failed", "misslyckad"},
		{"expiring", "utgår"},
		{"established", "upprättad"},
		{"unknown", "okänt"},
		{"exploratory", "utforskande"},
		{"Purple I2P Webconsole", "Purple I2P Webbkonsoll"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b>-Webbkonsoll"},
		{"Main page", "Huvudsida"},
		{"Router commands", "Routerkommandon"},
		{"Local Destinations", "Lokala Platser"},
		{"LeaseSets", "Hyresuppsättningar"},
		{"Tunnels", "Tunnlar"},
		{"Transit Tunnels", "Förmedlande Tunnlar"},
		{"Transports", "Transporter"},
		{"I2P tunnels", "I2P-tunnlar"},
		{"SAM sessions", "SAM-perioder"},
		{"ERROR", "FEL"},
		{"OK", "OK"},
		{"Testing", "Prövar"},
		{"Firewalled", "Bakom Brandvägg"},
		{"Unknown", "Okänt"},
		{"Proxy", "Proxy"},
		{"Mesh", "Mesh"},
		{"Clock skew", "Tidsförskjutning"},
		{"Offline", "Nedkopplad"},
		{"Symmetric NAT", "Symmetrisk NAT"},
		{"Full cone NAT", "Full kon NAT"},
		{"No Descriptors", "Inga Beskrivningar"},
		{"Uptime", "Upptid"},
		{"Network status", "Nätverkstillstånd"},
		{"Network status v6", "Nätverkstillstånd v6"},
		{"Stopping in", "Avstängd om"},
		{"Family", "Familj"},
		{"Tunnel creation success rate", "Andel framgångsrika tunnlar"},
		{"Received", "Mottaget"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Skickat"},
		{"Transit", "Förmedlat"},
		{"Data path", "Sökväg"},
		{"Hidden content. Press on text to see.", "Dolt innehåll. Tryck för att visa."},
		{"Router Ident", "Routeridentitet"},
		{"Router Family", "Routerfamilj"},
		{"Router Caps", "Routerbegränsningar"},
		{"Version", "Version"},
		{"Our external address", "Vår externa adress"},
		{"supported", "stöds"},
		{"Routers", "Routrar"},
		{"Floodfills", "Översvämningsfyllare"},
		{"Client Tunnels", "Klienttunnlar"},
		{"Services", "Tjänster"},
		{"Enabled", "Påslaget"},
		{"Disabled", "Avslaget"},
		{"Encrypted B33 address", "Krypterad B33-Adress"},
		{"Address registration line", "Adressregistreringsrad"},
		{"Domain", "Domän"},
		{"Generate", "Skapa"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Uppmärksamma:</b> den resulterande strängen kan enbart användas för att registrera 2LD-domäner (exempel.i2p). För att registrera underdomäner, vänligen använd i2pd-tools."},
		{"Address", "Adress"},
		{"Type", "Typ"},
		{"EncType", "EncTyp"},
		{"Inbound tunnels", "Ingående Tunnlar"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Utgående Tunnlar"},
		{"Tags", "Taggar"},
		{"Incoming", "Ingående"},
		{"Outgoing", "Utgående"},
		{"Destination", "Plats"},
		{"Amount", "Mängd"},
		{"Incoming Tags", "Ingående Taggar"},
		{"Tags sessions", "Tagg-perioder"},
		{"Status", "Tillstånd"},
		{"Local Destination", "Lokal Plats"},
		{"Streams", "Strömmar"},
		{"Close stream", "Stäng strömmen"},
		{"Such destination is not found", "En sådan plats hittas ej"},
		{"I2CP session not found", "I2CP-period hittades inte"},
		{"I2CP is not enabled", "I2CP är inte påslaget"},
		{"Invalid", "Ogiltig"},
		{"Store type", "Lagringstyp"},
		{"Expires", "Utgångsdatum"},
		{"Non Expired Leases", "Ickeutgångna Hyresuppsättningar"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "EndDate"},
		{"floodfill mode is disabled", "Floodfill läget är inaktiverat"},
		{"Queue size", "Köstorlek"},
		{"Run peer test", "Utför utsiktstest"},
		{"Reload tunnels configuration", "Ladda om tunnelkonfiguration"},
		{"Decline transit tunnels", "Avvisa förmedlande tunnlar"},
		{"Accept transit tunnels", "Tillåt förmedlande tunnlar"},
		{"Cancel graceful shutdown", "Avbryt välvillig avstängning"},
		{"Start graceful shutdown", "Påbörja välvillig avstängning"},
		{"Force shutdown", "Tvingad avstängning"},
		{"Reload external CSS styles", "Ladda om externa CSS-stilar"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Uppmärksamma:</b> inga ändringar här är beständiga eller påverkar dina inställningsfiler."},
		{"Logging level", "Protokollförningsnivå"},
		{"Transit tunnels limit", "Begränsa förmedlande tunnlar"},
		{"Change", "Ändra"},
		{"Change language", "Ändra språk"},
		{"no transit tunnels currently built", "inga förmedlande tunnlar har byggts"},
		{"SAM disabled", "SAM avslaget"},
		{"no sessions currently running", "inga perioder igång"},
		{"SAM session not found", "SAM-perioder hittades ej"},
		{"SAM Session", "SAM-period"},
		{"Server Tunnels", "Värdtunnlar"},
		{"Client Forwards", "Klientförpassningar"},
		{"Server Forwards", "Värdförpassningar"},
		{"Unknown page", "Okänd sida"},
		{"Invalid token", "Ogiltig polett"},
		{"SUCCESS", "FRAMGÅNG"},
		{"Stream closed", "Ström stängd"},
		{"Stream not found or already was closed", "Strömmen hittades inte eller var redan avslutad"},
		{"Destination not found", "Plats hittades ej"},
		{"StreamID can't be null", "Ström-ID kan inte vara null"},
		{"Return to destination page", "Återvänd till platssidan"},
		{"You will be redirected in %d seconds", "Du omdirigeras inom %d sekunder"},
		{"Transit tunnels count must not exceed %d", "Förmedlande tunnlar får inte överstiga %d"},
		{"Back to commands list", "Tillbaka till kommandolistan"},
		{"Register at reg.i2p", "Registrera vid reg.i2p"},
		{"Description", "Beskrivning"},
		{"A bit information about service on domain", "Ett stycke information om domänens tjänst"},
		{"Submit", "Skicka"},
		{"Domain can't end with .b32.i2p", "Domänen får inte sluta med .b32.i2p"},
		{"Domain must end with .i2p", "Domänen måste sluta med .i2p"},
		{"Unknown command", "Okänt kommando"},
		{"Command accepted", "Kommando accepterades"},
		{"Proxy error", "Proxyfel"},
		{"Proxy info", "Proxyinfo"},
		{"Proxy error: Host not found", "Proxyfel: Värden hittades ej"},
		{"Remote host not found in router's addressbook", "Främmande värd hittades inte i routerns adressbok"},
		{"You may try to find this host on jump services below", "Du kan försöka att hitta värden genom hopptjänsterna nedan"},
		{"Invalid request", "Ogiltig förfrågan"},
		{"Proxy unable to parse your request", "Proxyt kan inte behandla din förfrågan"},
		{"Addresshelper is not supported", "Adresshjälparen stöds ej"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Värd %s är <font color=red>redan i routerns adressbok</font>. <b>Var försiktig: källan till denna URL kan vara skadlig!</b> Klicka här för att uppdatera registreringen: <a href=\"%s%s%s&update=true\">Fortsätt</a>."},
		{"Addresshelper forced update rejected", "Tvingad uppdatering av adresshjälparen nekad"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "För att lägga till värd <b>%s</b> i routerns adressbok, klicka här: <a href=\"%s%s%s\">Fortsätt</a>."},
		{"Addresshelper request", "Adresshjälpare förfrågan"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Värd %s tillagd i routerns adressbok från hjälparen. Klicka här för att fortsätta: <a href=\"%s\">Fortsätt</a>."},
		{"Addresshelper adding", "Adresshjälpare tilläggning"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Värd %s är <font color=red>redan i routerns adressbok</font>. Klicka här för att uppdatera registreringen: <a href=\"%s%s%s&update=true\">Fortsätt</a>."},
		{"Addresshelper update", "Adresshjälpare uppdatering"},
		{"Invalid request URI", "Ogiltig förfrågnings-URI"},
		{"Can't detect destination host from request", "Kan inte upptäcka platsvärden från förfrågan"},
		{"Outproxy failure", "Utproxyfel"},
		{"Bad outproxy settings", "Ogiltig utproxyinställning"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Värd %s är inte inom I2P-näverket, men utproxy är inte påslaget"},
		{"Unknown outproxy URL", "okänt Utproxy-URL"},
		{"Cannot resolve upstream proxy", "Hittar inte uppströmsproxyt"},
		{"Hostname is too long", "Värdnamnet är för långt"},
		{"Cannot connect to upstream SOCKS proxy", "Kan inte ansluta till uppström SOCKS-proxy"},
		{"Cannot negotiate with SOCKS proxy", "Kan inte förhandla med SOCKSproxyt"},
		{"CONNECT error", "CONNECT-fel"},
		{"Failed to connect", "Anslutningen misslyckades"},
		{"SOCKS proxy error", "SOCKSproxyfel"},
		{"Failed to send request to upstream", "Förfrågan uppströms kunde ej skickas"},
		{"No reply from SOCKS proxy", "Fick inget svar från SOCKSproxyt"},
		{"Cannot connect", "Kan inte ansluta"},
		{"HTTP out proxy not implemented", "HTTP-Utproxy ej implementerat"},
		{"Cannot connect to upstream HTTP proxy", "Kan inte ansluta till uppströms HTTP-proxy"},
		{"Host is down", "Värden är nere"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Kan inte ansluta till värden, den kan vara nere. Vänligen försök senare."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d dag", "%d dagar"}},
		{"%d hours", {"%d timme", "%d timmar"}},
		{"%d minutes", {"%d minut", "%d minuter"}},
		{"%d seconds", {"%d sekund", "%d sekunder"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p

