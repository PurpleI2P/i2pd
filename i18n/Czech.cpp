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

// Czech localization file

namespace i2p
{
namespace i18n
{
namespace czech // language namespace
{
	// language name in lowercase
	static std::string language = "czech";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return (n == 1) ? 0 : (n >= 2 && n <= 4) ? 1 : 2;
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "vytváří se"},
		{"failed", "selhalo"},
		{"expiring", "končící"},
		{"established", "vytvořeno"},
		{"unknown", "neznámý"},
		{"exploratory", "průzkumné"},
		{"Purple I2P Webconsole", "Purple I2P Webkonsole"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> webkonsole"},
		{"Main page", "Hlavní stránka"},
		{"Router commands", "Router příkazy"},
		{"Local Destinations", "Lokální destinace"},
		{"LeaseSets", "LeaseSety"},
		{"Tunnels", "Tunely"},
		{"Transit Tunnels", "Transitní tunely"},
		{"Transports", "Transporty"},
		{"I2P tunnels", "I2P tunely"},
		{"SAM sessions", "SAM relace"},
		{"ERROR", "CHYBA"},
		{"OK", "OK"},
		{"Testing", "Testuji"},
		{"Firewalled", "Za Firewallem"},
		{"Unknown", "Neznámý"},
		{"Proxy", "Proxy"},
		{"Mesh", "Síť"},
		{"Clock skew", "Časová nesrovnalost"},
		{"Offline", "Offline"},
		{"Symmetric NAT", "Symetrický NAT"},
		{"Uptime", "Doba provozu"},
		{"Network status", "Status sítě"},
		{"Network status v6", "Status sítě v6"},
		{"Stopping in", "Zastavuji za"},
		{"Family", "Rodina"},
		{"Tunnel creation success rate", "Úspěšnost vytváření tunelů"},
		{"Received", "Přijato"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Odesláno"},
		{"Transit", "Tranzit"},
		{"Data path", "Cesta k data souborům"},
		{"Hidden content. Press on text to see.", "Skrytý kontent. Pro zobrazení, klikni na text."},
		{"Router Ident", "Routerová Identita"},
		{"Router Family", "Rodina routerů"},
		{"Router Caps", "Omezení Routerů"},
		{"Version", "Verze"},
		{"Our external address", "Naše externí adresa"},
		{"supported", "podporováno"},
		{"Routers", "Routery"},
		{"Floodfills", "Floodfilly"},
		{"Client Tunnels", "Klientské tunely"},
		{"Services", "Služby"},
		{"Enabled", "Zapnuto"},
		{"Disabled", "Vypnuto"},
		{"Encrypted B33 address", "Šifrovaná adresa B33"},
		{"Address registration line", "Registrační řádek adresy"},
		{"Domain", "Doména"},
		{"Generate", "Vygenerovat"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Poznámka:</b> výsledný řetězec může být použit pouze pro registraci 2LD domén (example.i2p). Pro registraci subdomén použijte prosím i2pd-tools."},
		{"Address", "Adresa"},
		{"Type", "Typ"},
		{"EncType", "EncType"},
		{"Inbound tunnels", "Příchozí tunely"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Odchozí tunely"},
		{"Tags", "Štítky"},
		{"Incoming", "Příchozí"},
		{"Outgoing", "Odchozí"},
		{"Destination", "Destinace"},
		{"Amount", "Množství"},
		{"Incoming Tags", "Příchozí štítky"},
		{"Tags sessions", "Relace štítků"},
		{"Status", "Status"},
		{"Local Destination", "Lokální Destinace"},
		{"Streams", "Toky"},
		{"Close stream", "Uzavřít tok"},
		{"I2CP session not found", "I2CP relace nenalezena"},
		{"I2CP is not enabled", "I2CP není zapnuto"},
		{"Invalid", "Neplatný"},
		{"Store type", "Druh uložení"},
		{"Expires", "Vyprší"},
		{"Non Expired Leases", "Nevypršené Leasy"},
		{"Gateway", "Brána"},
		{"TunnelID", "ID tunelu"},
		{"EndDate", "Datum ukončení"},
		{"Queue size", "Velikost fronty"},
		{"Run peer test", "Spustit peer test"},
		{"Decline transit tunnels", "Odmítnout tranzitní tunely"},
		{"Accept transit tunnels", "Přijmout tranzitní tunely"},
		{"Cancel graceful shutdown", "Zrušit hladké vypnutí"},
		{"Start graceful shutdown", "Zahájit hladké vypnutí"},
		{"Force shutdown", "Vynutit vypnutí"},
		{"Reload external CSS styles", "Znovu načíst externí CSS"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Poznámka:</b> žádná vykonaná akce zde není trvalá a nemění konfigurační soubory."},
		{"Logging level", "Úroveň logování"},
		{"Transit tunnels limit", "Limit tranzitních tunelů"},
		{"Change", "Změnit"},
		{"Change language", "Změnit jazyk"},
		{"no transit tunnels currently built", "Žádný tranzitní tunel není momentálně vytvořen"},
		{"SAM disabled", "SAM vypnutý"},
		{"no sessions currently running", "Momentálně nejsou spuštěné žádné relace"},
		{"SAM session not found", "SAM relace nenalezena"},
		{"SAM Session", "SAM Relace"},
		{"Server Tunnels", "Server Tunely"},
		{"Client Forwards", "Přesměrování Klienta"},
		{"Server Forwards", "Přesměrování Serveru"},
		{"Unknown page", "Neznámá stránka"},
		{"Invalid token", "Neplatný token"},
		{"SUCCESS", "ÚSPĚCH"},
		{"Stream closed", "Tok uzavřen"},
		{"Stream not found or already was closed", "Tok nenalezen nebo byl již uzavřen"},
		{"Destination not found", "Destinace nenalezena"},
		{"StreamID can't be null", "StreamID nemůže být null"},
		{"Return to destination page", "Zpět na stránku destinací"},
		{"Back to commands list", "Zpět na list příkazů"},
		{"Register at reg.i2p", "Zaregistrovat na reg.i2p"},
		{"Description", "Popis"},
		{"A bit information about service on domain", "Trochu informací o službě na doméně"},
		{"Submit", "Odeslat"},
		{"Domain can't end with .b32.i2p", "Doména nesmí končit na .b32.i2p"},
		{"Domain must end with .i2p", "Doména musí končit s .i2p"},
		{"Such destination is not found", "Takováto destinace nebyla nalezena"},
		{"Unknown command", "Neznámý příkaz"},
		{"Command accepted", "Příkaz přijat"},
		{"Proxy error", "Chyba proxy serveru"},
		{"Proxy info", "Proxy informace"},
		{"Proxy error: Host not found", "Chyba proxy serveru: Hostitel nenalezen"},
		{"Remote host not found in router's addressbook", "Vzdálený hostitel nebyl nalezen v adresáři routeru"},
		{"You may try to find this host on jump services below", "Můžete se pokusit najít tohoto hostitele na startovacích službách níže"},
		{"Invalid request", "Neplatný požadavek"},
		{"Proxy unable to parse your request", "Proxy server nemohl zpracovat váš požadavek"},
		{"Invalid request URI", "Neplatný URI požadavek"},
		{"Can't detect destination host from request", "Nelze zjistit cílového hostitele z požadavku"},
		{"Outproxy failure", "Outproxy selhání"},
		{"Bad outproxy settings", "Špatné outproxy nastavení"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Hostitel %s není uvnitř I2P sítě a outproxy není nastavena"},
		{"Unknown outproxy URL", "Neznámá outproxy URL"},
		{"Cannot resolve upstream proxy", "Nelze rozluštit upstream proxy server"},
		{"Hostname is too long", "Název hostitele je příliš dlouhý"},
		{"Cannot connect to upstream SOCKS proxy", "Nelze se připojit k upstream SOCKS proxy serveru"},
		{"Cannot negotiate with SOCKS proxy", "Nelze vyjednávat se SOCKS proxy serverem"},
		{"CONNECT error", "Chyba PŘIPOJENÍ"},
		{"Failed to connect", "Připojení se nezdařilo"},
		{"SOCKS proxy error", "Chyba SOCKS proxy serveru"},
		{"Failed to send request to upstream", "Odeslání žádosti upstream serveru se nezdařilo"},
		{"No reply from SOCKS proxy", "Žádná odpověď od SOCKS proxy serveru"},
		{"Cannot connect", "Nelze se připojit"},
		{"HTTP out proxy not implemented", "HTTP out proxy není implementován"},
		{"Cannot connect to upstream HTTP proxy", "Nelze se připojit k upstream HTTP proxy serveru"},
		{"Host is down", "Hostitel je nedostupný"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Připojení k požadovanému hostiteli nelze vytvořit, může být nedostupný. Zkuste to, prosím, znovu později."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d den", "%d dny", "%d dní", "%d dní"}},
		{"%d hours", {"%d hodina", "%d hodiny", "%d hodin", "%d hodin"}},
		{"%d minutes", {"%d minuta", "%d minuty", "%d minut", "%d minut"}},
		{"%d seconds", {"%d vteřina", "%d vteřiny", "%d vteřin", "%d vteřin"}},
		{"", {"", "", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
