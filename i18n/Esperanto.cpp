/*
* Copyright (c) 2026, The PurpleI2P Project
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

// Esperanto localization file

namespace i2p
{
namespace i18n
{
namespace esperanto // language namespace
{
	// language name in lowercase
	static std::string language = "esperanto";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	// Right to Left language?
	static bool rtl = false;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "konstruas"},
		{"failed", "malsukceso"},
		{"expiring", "pasas"},
		{"established", "funkcias"},
		{"unknown", "nesciate"},
		{"exploratory", "esplora"},
		{"Purple I2P Webconsole", "Reteja Konzolo de Purple I2P"},
		{"<b>i2pd</b> webconsole", "Reteja konzolo de <b>i2pd</b>"},
		{"Main page", "Ĉefa paĝo"},
		{"Router commands", "Enkursigilaj komandoj"},
		{"Local Destinations", "Lokaj destinaĵoj"},
		{"LeaseSets", "Luaĵoj"},
		{"Tunnels", "Tuneloj"},
		{"Transit Tunnels", "Transitaj tuneloj"},
		{"Transports", "Transportoj"},
		{"I2P tunnels", "I2P tuneloj"},
		{"SAM sessions", "SAM sesioj"},
		{"ERROR", "ERARO"},
		{"OK", "BONE"},
		{"Testing", "Ekzamenas"},
		{"Firewalled", "Fajromuro"},
		{"Unknown", "Nesciate"},
		{"Proxy", "Prokurilo"},
		{"Mesh", "Maŝo"},
		{"Clock skew", "Tempa oblikviĝo"},
		{"Offline", "Eksterrete"},
		{"Symmetric NAT", "Simetria NAT"},
		{"Full cone NAT", "Plenkonusa NAT"},
		{"No Descriptors", "Malhavas priskribilojn"},
		{"Uptime", "Funkcidaŭro"},
		{"Network status", "Reta statuso"},
		{"Network status v6", "Reta statuso v6"},
		{"Stopping in", "Ĝis haltigo restis"},
		{"Family", "Familio"},
		{"Tunnel creation success rate", "Sukcese konstruitaj tuneloj"},
		{"Total tunnel creation success rate", "Tute sukceseco de tunela konstruado"},
		{"Received", "Ricevite"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Sendite"},
		{"Transit", "Transito"},
		{"Data path", "Vojo al datumoj"},
		{"Hidden content. Press on text to see.", "Kaŝitaj informoj. Alklaku ĉi tie por malkovri."},
		{"Router Ident", "Enkursigila identigilo"},
		{"Router Family", "Enkursigila familio"},
		{"Router Caps", "Enkursigilaj markoj"},
		{"Version", "Versio"},
		{"Our external address", "Nia ekstera adreso"},
		{"supported", "subtenas"},
		{"Routers", "Enkursigiloj"},
		{"Floodfills", "Inundiloj"},
		{"Client Tunnels", "Klientaj tuneloj"},
		{"Services", "Priserviloj"},
		{"Enabled", "Ŝaltite"},
		{"Disabled", "Malŝaltite"},
		{"Encrypted B33 address", "Ĉifrita B33-adreso"},
		{"Address registration line", "Adresa registrada ĉeno"},
		{"Domain", "Domajno"},
		{"Generate", "Generi"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Rimarko:</b> la rezultan ĉenon vi povas uzi nur por registrado de duanivelaj domajnoj (ekz. example.i2p). Por registrado de subdomajnoj uzu i2pd-tools'n."},
		{"Address", "Adreso"},
		{"Type", "Tipo"},
		{"EncType", "Tipo de ĉifro"},
		{"Expire LeaseSet", "Pasigu luaĵon"},
		{"Inbound tunnels", "Ricevataj tuneloj"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Sendataj tuneloj"},
		{"Tags", "Etikedoj"},
		{"Incoming", "Ricevatoj"},
		{"Outgoing", "Sendatoj"},
		{"Destination", "Destinaĵo"},
		{"Amount", "Kvanto"},
		{"Incoming Tags", "Ricevataj etikedoj"},
		{"Tags sessions", "Etikedaj sesioj"},
		{"Status", "Statuso"},
		{"Local Destination", "Loka destinaĵo"},
		{"Streams", "Fluoj"},
		{"Close stream", "Fermi fluon"},
		{"Such destination is not found", "Ne trovis tian destinaĵon"},
		{"I2CP session not found", "Ne trovis la sesion de I2CP"},
		{"I2CP is not enabled", "I2CP estas neŝaltita"},
		{"Invalid", "Misa"},
		{"Store type", "Tipo de konservilo"},
		{"Expires", "Pasas"},
		{"Non Expired Leases", "Malpasintaj luaĵoj"},
		{"Gateway", "Kluzo"},
		{"TunnelID", "Tunela identigilo"},
		{"EndDate", "Dato de fino"},
		{"floodfill mode is disabled", "la inundila konduto estas malŝaltita"},
		{"Queue size", "Amplekso de la vico"},
		{"Run peer test", "Startigi punkto-al-punktan testadon"},
		{"Reload tunnels configuration", "Reŝargi la tunelajn agordojn"},
		{"Decline transit tunnels", "Malakcepti transitajn tunelojn"},
		{"Accept transit tunnels", "Akcepti transitajn tunelojn"},
		{"Cancel graceful shutdown", "Nuligi la pravan haltigon"},
		{"Start graceful shutdown", "Startigi la pravan haltigon"},
		{"Force shutdown", "Perforte haltigi"},
		{"Reload external CSS styles", "Reŝargi eksterajn stilojn de CSS"},
		{"<b>Note:</b> any action performed here is not persistent and does not change your config files.", "<b>Rimarko:</b> ĉiu ago estante tie ne estas konstanta kaj ne ŝanĝis viajn dosierojn de la agordoj."},
		{"Logging level", "Nivelo de loka-raportado"},
		{"Transit tunnels limit", "Limigo de transitaj tuneloj"},
		{"Change", "Ŝanĝi"},
		{"Change language", "Ŝanĝi lingvon"},
		{"no transit tunnels currently built", "malhavas konstruitajn transitajn tunelojn"},
		{"SAM disabled", "SAM estas malŝaltita"},
		{"no sessions currently running", "malhavas funkciantajn sesiojn"},
		{"SAM session not found", "Ne trovis la sesion de SAM"},
		{"SAM Session", "Sesio de SAM"},
		{"Server Tunnels", "Servilaj tuneloj"},
		{"Client Forwards", "Klientaj alidirektoj"},
		{"Server Forwards", "Servilaj alidirektoj"},
		{"Unknown page", "Nesciata paĝo"},
		{"Invalid token", "Misa ĵetono"},
		{"SUCCESS", "SUKCESO"},
		{"Stream closed", "Fermita fluo"},
		{"Stream not found or already was closed", "Ne trovis la fluon aŭ la fluo jam estis fermita"},
		{"Destination not found", "Ne trovis la destinaĵon"},
		{"StreamID can't be null", "Flua identigilo ne povas esti nula"},
		{"Return to destination page", "Returni al la destinaĵa paĝo"},
		{"You will be redirected in %d seconds", "Vin alidirektos tra %d sekundoj"},
		{"LeaseSet expiration time updated", "Ŝanĝis la luaĵan pas-tempon"},
		{"LeaseSet is not found or already expired", "Ne trovis la luaĵon aŭ la luaĵo jam estis pasinta"},
		{"Transit tunnels count must not exceed %d", "Kvanto da transitaj tuneloj devas nesuperi %d"},
		{"Back to commands list", "Returni al la listo de komandoj"},
		{"Register at reg.i2p", "Registri per reg.i2p"},
		{"Description", "Priskribo"},
		{"A bit information about service on domain", "Iomete informoj pri priservilo je la domajno"},
		{"Submit", "Sendi"},
		{"Domain can't end with .b32.i2p", "Domajno ne povas finiĝi per .b32.i2p"},
		{"Domain must end with .i2p", "Domajno devas finiĝi per .i2p"},
		{"Unknown command", "Nesciata komando"},
		{"Command accepted", "Komando estas akceptita"},
		{"Proxy error", "Eraro de prokurilo"},
		{"Proxy info", "Informo pri prokurilo"},
		{"Proxy error: Host not found", "Eraro de prokurilo: Ne trovis la retnodon"},
		{"Remote host not found in router's addressbook", "Ne trovis la foran retnodon en la enkursigila adreslibro"},
		{"You may try to find this host on jump services below", "Vi povas provi trovi ĉi tiun retnodon per ĉi tiuj salt-serviloj"},
		{"Invalid request", "Misa peto"},
		{"Proxy unable to parse your request", "Prokurilo ne povas analizi vian peton"},
		{"Addresshelper is not supported", "Adreshelpilon ne subtenas"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Retnodo %s <font color=red>jam estas en la enkursigila adreslibro</font>. <b>Estu atente: fonto de tiu URL povas esti danĝere!</b> Alklaku ĉi tie por renovigi la skribon: <a href=\"%s%s%s&update=true\">Daŭrige</a>."},
		{"Addresshelper forced update rejected", "Perforta renovigo de la adreshelpilo estas rifuzita"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Por aldono de la retnodo <b>%s</b> en la enkursigila adreslibro, alklaku ĉi tie: <a href=\"%s%s%s\">Daŭrige</a>."},
		{"Addresshelper request", "Peto por aldono de adreshelpilo"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Retnodon %s aldonis en la enkursigila adreslibro per la adreshelpilo. Alklaku ĉi tie por daŭrigo: <a href=\"%s\">Daŭrige</a>."},
		{"Addresshelper adding", "Aldono de la adreshelpilo"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Retnodo %s <font color=red>jam estas en la enkursigila adreslibro</font>. Alklaku ĉi tie por renovigi la skribon: <a href=\"%s%s%s&update=true\">Daŭrige</a>."},
		{"Addresshelper update", "Renovigo de la skribo per la adreshelpilo"},
		{"Invalid request URI", "Misa URI de la peto"},
		{"Can't detect destination host from request", "Ne povas determeni la destinaĵan retnodon el la peto"},
		{"Outproxy failure", "Eraro de ekster-prokurilo"},
		{"Bad outproxy settings", "Misaj agordoj de ekster-prokurilo"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Retnodo %s ne estas ene de I2P reto, tamen la ekster-prokurilo estas malŝaltita"},
		{"Unknown outproxy URL", "Nesciata URL de ekster-prokurilo"},
		{"Cannot resolve upstream proxy", "Ne povas determeni la supra-prokurilon"},
		{"Hostname is too long", "Retnoda nomo estas tro longa"},
		{"Cannot connect to upstream SOCKS proxy", "Malsukcesis konekti kun la supra-prokurilo de SOCKS"},
		{"Cannot negotiate with SOCKS proxy", "Ne povas interkonsenti kun la prokurilo de SOCKS"},
		{"CONNECT error", "eraro de KONEKTO"},
		{"Failed to connect", "Malsukcesis konekti"},
		{"SOCKS proxy error", "Prokurila eraro de SOCKS"},
		{"Failed to send request to upstream", "Malsukcesis sendi peton al superaĵo"},
		{"No reply from SOCKS proxy", "Malhavas respondon disde la prokurilo de SOCKS"},
		{"Cannot connect", "Ne povas konekti"},
		{"HTTP out proxy not implemented", "Subteno de la ekster-prokurilo ne estas realigita"},
		{"Cannot connect to upstream HTTP proxy", "Ne povas konekti kun la supera-prokurilo de HTTP"},
		{"Host is down", "Retnodo estas eksterreta"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Ne povas krei konekton kun la petita retnodo, eble ĝi estas eksterreta. Bonvolu provi poste."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d tago", "%d tagoj"}},
		{"%d hours", {"%d horo", "%d horoj"}},
		{"%d minutes", {"%d minuto", "%d minutoj"}},
		{"%d seconds", {"%d sekundo", "%d sekundo"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
