/*
* Copyright (c) 2021-2023, The PurpleI2P Project
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

// Turkmen localization file

namespace i2p
{
namespace i18n
{
namespace turkmen // language namespace
{
	// language name in lowercase
	static std::string language = "turkmen";

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
		{"building", "bina"},
		{"failed", "şowsuz"},
		{"expiring", "möhleti gutarýar"},
		{"established", "işleýär"},
		{"unknown", "näbelli"},
		{"exploratory", "gözleg"},
		{"Purple I2P Webconsole", "Web konsoly Purple I2P"},
		{"<b>i2pd</b> webconsole", "Web konsoly <b>i2pd</b>"},
		{"Main page", "Esasy sahypa"},
		{"Router commands", "Marşrutizator buýruklary"},
		{"Local Destinations", "Ýerli ýerler"},
		{"LeaseSets", "Lizset"},
		{"Tunnels", "Tuneller"},
		{"Transit Tunnels", "Tranzit Tunelleri"},
		{"Transports", "Daşamak"},
		{"I2P tunnels", "I2P tuneller"},
		{"SAM sessions", "SAM Sessiýasy"},
		{"ERROR", "Ýalňyşlyk"},
		{"OK", "OK"},
		{"Testing", "Synag etmek"},
		{"Firewalled", "Daşynda petiklendi"},
		{"Unknown", "Näbelli"},
		{"Proxy", "Proksi"},
		{"Mesh", "MESH-tor"},
		{"Clock skew", "Takyk wagt däl"},
		{"Offline", "Awtonom"},
		{"Symmetric NAT", "Simmetriklik NAT"},
		{"Uptime", "Onlaýn onlaýn sözlügi"},
		{"Network status", "Tor ýagdaýy"},
		{"Network status v6", "Tor ýagdaýy v6"},
		{"Stopping in", "Soň duruň"},
		{"Family", "Maşgala"},
		{"Tunnel creation success rate", "Gurlan teneller üstünlikli gurlan teneller"},
		{"Received", "Alnan"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Ýerleşdirildi"},
		{"Transit", "Tranzit"},
		{"Data path", "Maglumat ýoly"},
		{"Hidden content. Press on text to see.", "Gizlin mazmun. Görkezmek üçin tekste basyň."},
		{"Router Ident", "Marşrutly kesgitleýji"},
		{"Router Family", "Marşrutler maşgalasy"},
		{"Router Caps", "Baýdaklar marşruteri"},
		{"Version", "Wersiýasy"},
		{"Our external address", "Daşarky salgymyz"},
		{"supported", "goldanýar"},
		{"Routers", "Marşrutizatorlar"},
		{"Floodfills", "Fludfillar"},
		{"Client Tunnels", "Müşderi tunelleri"},
		{"Services", "Hyzmatlar"},
		{"Enabled", "Goşuldy"},
		{"Disabled", "Öçürildi"},
		{"Encrypted B33 address", "Şifrlenen B33 salgylar"},
		{"Address registration line", "Hasaba alyş salgysy"},
		{"Domain", "Domen"},
		{"Generate", "Öndürmek"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Bellik:</b> Alnan setir diňe ikinji derejeli domenleri bellige almak üçin ulanylyp bilner (example.i2p). Subýutmalary hasaba almak üçin i2pd ulanyň-tools."},
		{"Address", "Salgysy"},
		{"Type", "Görnüş"},
		{"EncType", "Şifrlemek görnüşi"},
		{"Inbound tunnels", "Gelýän tuneller"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Çykýan tuneller"},
		{"Tags", "Bellikler"},
		{"Incoming", "Gelýän"},
		{"Outgoing", "Çykýan"},
		{"Destination", "Maksat"},
		{"Amount", "Sany"},
		{"Incoming Tags", "Gelýän bellikler"},
		{"Tags sessions", "Sapaklar bellikler"},
		{"Status", "Ýagdaýy"},
		{"Local Destination", "Ýerli maksat"},
		{"Streams", "Strimlary"},
		{"Close stream", "Yap strim"},
		{"I2CP session not found", "I2CP Sessiýa tapylmady"},
		{"I2CP is not enabled", "I2CP goşulmaýar"},
		{"Invalid", "Nädogry"},
		{"Store type", "Ammar görnüşi"},
		{"Expires", "Möhleti gutarýar"},
		{"Non Expired Leases", "Möhleti gutarmady Lizsetlary"},
		{"Gateway", "Derweze"},
		{"TunnelID", "Tuneliň ID"},
		{"EndDate", "Gutarýar"},
		{"Queue size", "Nobatyň ululygy"},
		{"Run peer test", "Synag başlaň"},
		{"Decline transit tunnels", "Tranzit tunellerini ret ediň"},
		{"Accept transit tunnels", "Tranzit tunellerini alyň"},
		{"Cancel graceful shutdown", "Tekiz durmagy ýatyryň"},
		{"Start graceful shutdown", "Tekiz durmak"},
		{"Force shutdown", "Mejbury duralga"},
		{"Reload external CSS styles", "Daşarky CSS stillerini täzeden ýükläň"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Bellik:</b> Bu ýerde öndürilen islendik çäre hemişelik däl we konfigurasiýa faýllaryňyzy üýtgetmeýär."},
		{"Logging level", "Giriş derejesi"},
		{"Transit tunnels limit", "Tranzit tunelleriniň çägi"},
		{"Change", "Üýtgetmek"},
		{"Change language", "Dil üýtgetmek"},
		{"no transit tunnels currently built", "gurlan tranzit tunelleri ýok"},
		{"SAM disabled", "SAM öçürilen"},
		{"no sessions currently running", "başlamagyň sessiýalary ýok"},
		{"SAM session not found", "SAM Sessiýa tapylmady"},
		{"SAM Session", "SAM Sessiýa"},
		{"Server Tunnels", "Serwer tunelleri"},
		{"Client Forwards", "Müşderi gönükdirýär"},
		{"Server Forwards", "Serweriň täzeden düzlüleri"},
		{"Unknown page", "Näbelli sahypa"},
		{"Invalid token", "Nädogry token"},
		{"SUCCESS", "Üstünlikli"},
		{"Stream closed", "Strim ýapyk"},
		{"Stream not found or already was closed", "Strim tapylmady ýa-da eýýäm ýapyldy"},
		{"Destination not found", "Niýetlenen ýeri tapylmady"},
		{"StreamID can't be null", "StreamID boş bolup bilmez"},
		{"Return to destination page", "Barmaly nokadynyň nokadyna gaýdyp geliň"},
		{"Back to commands list", "Topar sanawyna dolan"},
		{"Register at reg.i2p", "Reg.i2P-de hasaba duruň"},
		{"Description", "Beýany"},
		{"A bit information about service on domain", "Domendäki hyzmat barada käbir maglumatlar"},
		{"Submit", "Iber"},
		{"Domain can't end with .b32.i2p", "Domain .b32.i2p bilen gutaryp bilmez"},
		{"Domain must end with .i2p", "Domeni .i2p bilen gutarmaly"},
		{"Such destination is not found", "Bu barmaly ýer tapylmady"},
		{"Unknown command", "Näbelli topar"},
		{"Command accepted", "Topar kabul edilýär"},
		{"Proxy error", "Proksi ýalňyşlygy"},
		{"Proxy info", "Proksi maglumat"},
		{"Proxy error: Host not found", "Proksi ýalňyşlygy: Host tapylmady"},
		{"Remote host not found in router's addressbook", "Uzakdaky öý eýesi marşruteriň salgy kitabynda tapylmady"},
		{"You may try to find this host on jump services below", "Aşakdaky böküş hyzmatlarynda bu öý eýesini tapmaga synanyşyp bilersiňiz"},
		{"Invalid request", "Nädogry haýyş"},
		{"Proxy unable to parse your request", "Proksi haýyşyňyzy derňäp bilmeýär"},
		{"Invalid request URI", "Nädogry haýyş URI"},
		{"Can't detect destination host from request", "Haýyşdan barmaly ýerini tapyp bilemok"},
		{"Outproxy failure", "Daşarky proksi ýalňyşlyk"},
		{"Bad outproxy settings", "Daşarky Daşarky proksi sazlamalary nädogry"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Adres %s I2P torunda däl, ýöne daşarky proksi goşulmaýar"},
		{"Unknown outproxy URL", "Näbelli daşarky proksi URL"},
		{"Cannot resolve upstream proxy", "Has ýokary proksi kesgitläp bilmeýär"},
		{"Hostname is too long", "Hoster eýesi ady gaty uzyn"},
		{"Cannot connect to upstream SOCKS proxy", "Ýokary jorap SOCKS proksi bilen birigip bolmaýar"},
		{"Cannot negotiate with SOCKS proxy", "Iň ýokary jorap SOCKS proksi bilen ylalaşyp bilmeýärler"},
		{"CONNECT error", "Bagyr haýyşy säwligi"},
		{"Failed to connect", "Birikdirip bilmedi"},
		{"SOCKS proxy error", "SOCKS proksi ýalňyşlygy"},
		{"Failed to send request to upstream", "Öý eýesi proksi üçin haýyş iberip bilmedi"},
		{"No reply from SOCKS proxy", "Jorap SOCKS proksi serwerinden hiç hili jogap ýok"},
		{"Cannot connect", "Birikdirip bilmedi"},
		{"HTTP out proxy not implemented", "Daşarky HTTP proksi serwerini goldamak amala aşyrylmaýar"},
		{"Cannot connect to upstream HTTP proxy", "Ýokary jorap HTTP proksi bilen birigip bolmaýar"},
		{"Host is down", "Salgy elýeterli däl"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Talap edilýän salgyda birikmäni gurup bilmedim, onlaýn bolup bilmez. Soňra haýyşy soň gaýtalamaga synanyşyň."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days",    {"%d gün", "%d gün"}},
		{"%d hours",   {"%d sagat", "%d sagat"}},
		{"%d minutes", {"%d minut", "%d minut"}},
		{"%d seconds", {"%d sekunt", "%d sekunt"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
