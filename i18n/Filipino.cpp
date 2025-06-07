/*
* Copyright (c) 2021-2025, The PurpleI2P Project
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

// Russian localization file

namespace i2p
{
namespace i18n
{
namespace filipino // language namespace
{
	// language name in lowercase
	static std::string language = "filipino";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 && n != 2 && n != 3 && (n % 10 == 4 || n % 10 == 6 || n % 10 == 9);
	}

	// Right to Left language?
	static bool rtl = false;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "ginagawa"},
		{"failed", "nabigo"},
		{"expiring", "nage-expire"},
		{"established", "na-establish"},
		{"unknown", "hindi alam"},
		{"exploratory", "eksplorasyon"},
		{"Purple I2P Webconsole", "Webconsole ng Purple I2P"},
		{"<b>i2pd</b> webconsole", "Webconsole ng <b>i2pd</b>"},
		{"Main page", "Unang pahina"},
		{"Router commands", "Mga utos sa router"},
		{"Local Destinations", "Mga lokal na patutunguhan"},
		{"LeaseSets", "Mga LeaseSet"},
		{"Tunnels", "Mga Tunnel"},
		{"Transit Tunnels", "Mga Transit Tunnel"},
		{"Transports", "Mga Transport"},
		{"I2P tunnels", "Mga I2P tunnel"},
		{"SAM sessions", "Mga session ng SAM"},
		{"ERROR", "ERROR"},
		{"OK", "OK"},
		{"Testing", "Sinusubukan"},
		{"Firewalled", "Naka-firewall"},
		{"Unknown", "Hindi alam"},
		{"Proxy", "Proxy"},
		{"Mesh", "Mesh"},
		{"Clock skew", "Clock skew"},
		{"Offline", "Оffline"},
		{"Symmetric NAT", "Symmetric na NAT"},
		{"Full cone NAT", "Full cone na NAT"},
		{"No Descriptors", "Walang mga Deskriptor"},
		{"Uptime", "Uptime"},
		{"Network status", "Status ng network"},
		{"Network status v6", "Status ng v6 network"},
		{"Stopping in", "Titigil sa"},
		{"Family", "Pamilya"},
		{"Tunnel creation success rate", "Rate ng matagumpay na paggawa ng tunnel"},
		{"Total tunnel creation success rate", "Kabuuang rate ng matagumpay na paggawa ng tunnel"},
		{"Received", "Natanggap"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Napadala"},
		{"Transit", "Transit"},
		{"Data path", "Path ng data"},
		{"Hidden content. Press on text to see.", "Nakatagong nilalaman. Pintutin ang text para makita."},
		{"Router Ident", "Pagkakilanlan ng Router"},
		{"Router Family", "Pamilya ng Router"},
		{"Router Caps", "Kakayahan ng Router"},
		{"Version", "Bersyon"},
		{"Our external address", "Ating external address"},
		{"supported", "sinusuportahan"},
		{"Routers", "Mga Router"},
		{"Floodfills", "Mga Floodfill"},
		{"Client Tunnels", "Mga Client Tunnel"},
		{"Services", "Mga Serbisyo"},
		{"Enabled", "Naka-enable"},
		{"Disabled", "Naka-disable"},
		{"Encrypted B33 address", "Naka-encrypt na B33 address"},
		{"Address registration line", "Linya ng pagrehistro ng address"},
		{"Domain", "Domain"},
		{"Generate", "I-generate"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Tandaan:</b> maaari lamang gamitin ang string ng resulta para sa pagrehistro ng mga 2LD domain (example.i2p). Para sa pagrehistro ng mga subdomain mangyaring gamitin ang i2pd-tools."},
		{"Address", "Address"},
		{"Type", "Uri"},
		{"EncType", "Uri ng encryption"},
		{"Expire LeaseSet", "I-expire ang LeaseSet"},
		{"Inbound tunnels", "Mga papasok na tunnel"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Mga palabas na tunnel"},
		{"Tags", "Mga Tag"},
		{"Incoming", "Papasok"},
		{"Outgoing", "Palabas"},
		{"Destination", "Patutunguhan"},
		{"Amount", "Halaga"},
		{"Incoming Tags", "Mga Papasok na Tag"},
		{"Tags sessions", "Mga tag session"},
		{"Status", "Status"},
		{"Local Destination", "Lokal na Patutunguhan"},
		{"Streams", "Mga stream"},
		{"Close stream", "Isara ang strea,"},
		{"Such destination is not found", "Hindi mahanap ang patutunguhan"},
		{"I2CP session not found", "Hindi mahanap ang I2CP session"},
		{"I2CP is not enabled", "Hindi naka-enable ang I2CP"},
		{"Invalid", "Hindi wasto"},
		{"Store type", "Uri ng store"},
		{"Expires", "Mage-expire"},
		{"Non Expired Leases", "Mga Hindi Naka-expire na :ease"},
		{"Gateway", "Gateway"},
		{"TunnelID", "ID ng Tunnel"},
		{"EndDate", "Petsa ng pagtatapos"},
		{"floodfill mode is disabled", "Naka-disable ang floodfill mode"},
		{"Queue size", "Size ng queue"},
		{"Run peer test", "Patakbuhin ang pagsubok ng peer"},
		{"Reload tunnels configuration", "I-reload ang pagsasaayos ng tunnel"},
		{"Decline transit tunnels", "Tanggihan ang mga transit tunnel"},
		{"Accept transit tunnels", "Tanggapin ang mga transit tunnel"},
		{"Cancel graceful shutdown", "Kanselahin ang graceful na pag-shutdown"},
		{"Start graceful shutdown", "Simulan ang graceful na pag-shutdown"},
		{"Force shutdown", "Pilitin ang pagsa-shutdown"},
		{"Reload external CSS styles", "I-reload ang mga external na istilio ng CSS"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Tandaan</b>: hindi mananatili ang mga pagbabago na ito at hindi babaguhin ang iyong mga config file."},
		{"Logging level", "Antas ng pag-log"},
		{"Transit tunnels limit", "Limitasyon ng mga transit tunnel"},
		{"Change", "Baguhin"},
		{"Change language", "Baguhin ang wika"},
		{"no transit tunnels currently built", "Wala pang nagawang transit tunnel"},
		{"SAM disabled", "Naka-disable ang SAM"},
		{"no sessions currently running", "wala pang mga tumatakbo na session"},
		{"SAM session not found", "Hindi nahanap ang SAM session"},
		{"SAM Session", "SAM Session"},
		{"Server Tunnels", "Mga Server Tunnel"},
		{"Client Forwards", "Mga Client Forward"},
		{"Server Forwards", "Mga Server Forward"},
		{"Unknown page", "Hindi alam na pahina"},
		{"Invalid token", "Hindi wastong token"},
		{"SUCCESS", "MATAGUMPAY"},
		{"Stream closed", "Sinara ang stream"},
		{"Stream not found or already was closed", "Hindi nahanap ang stream o sinara na"},
		{"Destination not found", "Hindi nahanap ang patutunguhan"},
		{"StreamID can't be null", "Hindi maaaring null ang StreamID"},
		{"Return to destination page", "Bumalik sa pahina ng patutunguhan"},
		{"You will be redirected in %d seconds", "Mare-redirect ka sa %d segundo"},
		{"LeaseSet expiration time updated", "Na-update ang oras ng pag-expire ng LeaseSet"},
		{"LeaseSet is not found or already expired", "Hindi nahanap o nag-expire na ang LeaseSet"},
		{"Transit tunnels count must not exceed %d", "Hindi maaaring lumagpas sa %d ang bilang ng mga transit tunnel"},
		{"Back to commands list", "Bumalik sa listahan ng mga utos"},
		{"Register at reg.i2p", "I-rehistro sa reg.i2p"},
		{"Description", "Paglalarawan"},
		{"A bit information about service on domain", "Kaunting impormasyon tungkol sa serbisyo sa domain"},
		{"Submit", "I-submit"},
		{"Domain can't end with .b32.i2p", "Hindi maaaring matapos sa .b32.i2p ang domain"},
		{"Domain must end with .i2p", "Dapat matapos sa .i2p ang domain"},
		{"Unknown command", "Hindi alam na command"},
		{"Command accepted", "Tinanggap ang command"},
		{"Proxy error", "Error sa proxy"},
		{"Proxy info", "Info sa proxy"},
		{"Proxy error: Host not found", "Error sa proxy: Hindi nahanap ang host"},
		{"Remote host not found in router's addressbook", "Hindi nahanap ang remote host sa addressbook ng router"},
		{"You may try to find this host on jump services below", "Maaari mo subukang hanapin ang host na ito sa mga jump service sa ibaba"},
		{"Invalid request", "Hindi wastong hiling"},
		{"Proxy unable to parse your request", "Hindi ma-parse ng proxy ang iyong hiling"},
		{"Addresshelper is not supported", "Hindi sinusuportahan ang addresshelper"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "<font color=red>Nasa addressbook ng router na</font> ang host na %s. <b>Mag-ingat: baka mapanganib ang source ng URL na ito!</b> Mag-click dito para i-update ang record: <a href=\"%s%s%s&update=true\">Magpatuloy</a>."},
		{"Addresshelper forced update rejected", "Tinanggihan ang pinilit na pag-update ng addresshelper"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Para idagdag ang host na <b>%s</b> sa addressbook ng router, mag-click dito: <a href=\"%s%s%s\">Magpatuloy</a>."},
		{"Addresshelper request", "Hiling ng addresshelper"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Dinagdag ang host na %s sa addressbook ng router. Mag-click dito para magpatuloy: <a href=\"%s\">Magpatuloy</a>."},
		{"Addresshelper adding", "Pagdagdag sa addresshelper"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Узел %s <font color=red>уже в адресной книге роутера</font>. Нажмите здесь, чтобы обновить запись: <a href=\"%s%s%s&update=true\">Продолжить</a>."},
		{"Addresshelper update", "Pag-update sa addresshelper"},
		{"Invalid request URI", "Hindi wastong URI ng hiling"},
		{"Can't detect destination host from request", "Hindi ma-detect ang patutunguhang host mula sa hiling"},
		{"Outproxy failure", "Nabigong outproxy"},
		{"Bad outproxy settings", "Hindi wastong mga setting ng outproxy"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Hindi nasa loob ng I2P network ang %s, ngunit hindi naka-enable ang outproxy"},
		{"Unknown outproxy URL", "Hindi alam na outproxy URL"},
		{"Cannot resolve upstream proxy", "Hindi ma-resolve ang upstream proxy"},
		{"Hostname is too long", "Masyadong mahaba ang hostname"},
		{"Cannot connect to upstream SOCKS proxy", "Hindi makakonekta sa upstream SOCKS proxy"},
		{"Cannot negotiate with SOCKS proxy", "Hindi makapag-negotiate sa SOCKS proxy"},
		{"CONNECT error", "Error sa CONNECT"},
		{"Failed to connect", "Nabigong kumonekta"},
		{"SOCKS proxy error", "Error sa SOCKS proxy"},
		{"Failed to send request to upstream", "Nabigong ipadala ang hiling sa upstream"},
		{"No reply from SOCKS proxy", "Walang tugon mula sa SOCKS proxy"},
		{"Cannot connect", "Hindi makakonekta"},
		{"HTTP out proxy not implemented", "Hindi naka-implement ang HTTP out proxy"},
		{"Cannot connect to upstream HTTP proxy", "Hindi makakonekta sa upstream HTTP proxy"},
		{"Host is down", "Down ang host"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Hindi makagawa ng koneksyon sa hiniling na host, baka down ang host. Subukan muli mamaya."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days",    {"%d araw", "%d (na) araw"}},
		{"%d hours",   {"%d oras", "%d (na) oras"}},
		{"%d minutes", {"%d minuto", "%d (na) minuto"}},
		{"%d seconds", {"%d segundo", "%d (na) segundo"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
