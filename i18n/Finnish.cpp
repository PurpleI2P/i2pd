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

// Finnish localization file

namespace i2p
{
namespace i18n
{
namespace finnish // language namespace
{
	// language name in lowercase
	static std::string language = "finnish";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	// Right to Left language?
	static bool rtl = false;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f kt"},
		{"%.2f MiB", "%.2f Mt"},
		{"%.2f GiB", "%.2f Gt"},
		{"building", "rakentaa"},
		{"failed", "epäonnistui"},
		{"expiring", "vanhentumassa"},
		{"established", "muodostettu"},
		{"unknown", "tuntematon"},
		{"exploratory", "selvittely"},
		{"Purple I2P Webconsole", "Purple I2P web-konsoli"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> web-konsoli"},
		{"Main page", "Pääsivu"},
		{"Router commands", "Reitittimen komennot"},
		{"Local Destinations", "Paikalliset osoitteet"},
		{"LeaseSets", "LeaseSetit"},
		{"Tunnels", "Tunnelit"},
		{"Transit Tunnels", "Välitystunnelit"},
		{"Transports", "Siirtomenetelmät"},
		{"I2P tunnels", "I2P tunnelit"},
		{"SAM sessions", "SAM istunnot"},
		{"ERROR", "VIRHE"},
		{"OK", "OK"},
		{"Testing", "Testataan"},
		{"Firewalled", "Palomuurin takana"},
		{"Unknown", "Tuntematon"},
		{"Proxy", "Välityspalvelin"},
		{"Mesh", "Verkkopinta"},
		{"Clock skew", "Kellon synkronointivirhe"},
		{"Offline", "Offline-tilassa"},
		{"Symmetric NAT", "Symmetrinen NAT"},
		{"Full cone NAT", "Täyskartoitettu NAT"},
		{"No Descriptors", "Ei deskriptoritietoja"},
		{"Uptime", "Käynnissäoloaika"},
		{"Network status", "Verkon tila"},
		{"Network status v6", "Verkon tila v6"},
		{"Stopping in", "Pysäytetään"},
		{"Family", "Perhe"},
		{"Tunnel creation success rate", "Tunnelin luontiyritysten onnistumisprosentti"},
		{"Total tunnel creation success rate", "Tunnelien luontien kokonaisonnistumisprosentti"},
		{"Received", "Vastaanotettu"},
		{"%.2f KiB/s", "%.2f kt/s"},
		{"Sent", "Lähetetty"},
		{"Transit", "Siirto"},
		{"Data path", "Tiedostojen polku"},
		{"Hidden content. Press on text to see.", "Piilotettu sisältö. Paina tekstiä nähdäksesi."},
		{"Router Ident", "Reitittimen Identiteetti"},
		{"Router Family", "Reitittimen Perhe"},
		{"Router Caps", "Reitittimen ominaisuudet"},
		{"Version", "Versio"},
		{"Our external address", "Ulkoinen osoite"},
		{"supported", "tuettu"},
		{"Routers", "Reitittimet"},
		{"Floodfills", "Floodfill-solmut"},
		{"Client Tunnels", "Asiakkaan Tunnelit"},
		{"Services", "Palvelut"},
		{"Enabled", "Käytössä"},
		{"Disabled", "Poissa käytöstä"},
		{"Encrypted B33 address", "Salattu B33-osoite"},
		{"Address registration line", "Osoitteen rekisteröintirivi"},
		{"Domain", "Verkkotunnus"},
		{"Generate", "Luo"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Huom:</b> tulosmerkkijonoa voi käyttää vain 2. tason verkkotunnusten (esim. example.i2p) rekisteröintiin. Aliverkkotunnusten rekisteröintiin käytä i2pd-työkaluja."},
		{"Address", "Osoite"},
		{"Type", "Tyyppi"},
		{"EncType", "Salaustyyppi"},
		{"Expire LeaseSet", "LeaseSetin vanheneminen"},
		{"Inbound tunnels", "Saapuvat tunnelit"},
		{"%dms", "%d ms"},
		{"Outbound tunnels", "Lähtevät tunnelit"},
		{"Tags", "Tunnisteet"},
		{"Incoming", "Saapuva"},
		{"Outgoing", "Lähtevä"},
		{"Destination", "Kohde"},
		{"Amount", "Määrä"},
		{"Incoming Tags", "Saapuvat Tunnisteet"},
		{"Tags sessions", "Tunnisteiden istunnot"},
		{"Status", "Tila"},
		{"Local Destination", "Paikallinen Kohde"},
		{"Streams", "Streamit"},
		{"Close stream", "Sulje streami"},
		{"Such destination is not found", "Tällaista määränpäätä ei löydy"},
		{"I2CP session not found", "I2CP-istuntoa ei löytynyt"},
		{"I2CP is not enabled", "I2CP ei ole päällä"},
		{"Invalid", "Virheellinen"},
		{"Store type", "Tallennustyyppi"},
		{"Expires", "Vanhenee"},
		{"Non Expired Leases", "Vanhentumattomat leaset"},
		{"Gateway", "Yhdyskäytävä"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Päättymispäivä"},
		{"floodfill mode is disabled", "Floodfill-tila on poistettu käytöstä"},
		{"Queue size", "Jonon koko"},
		{"Run peer test", "Suorita yhteystesti"},
		{"Reload tunnels configuration", "Lataa tunnelikonfiguraatio uudelleen"},
		{"Decline transit tunnels", "Hylkää läpikulkutunnelit"},
		{"Accept transit tunnels", "Hyväksy läpikulkutunnelit"},
		{"Cancel graceful shutdown", "Keskeytä hallittu sulkeminen"},
		{"Start graceful shutdown", "Käynnistä hallittu sulkeminen"},
		{"Force shutdown", "Pakota sammutus"},
		{"Reload external CSS styles", "Lataa ulkoiset CSS-tyylit uudelleen"},
		{"<b>Note:</b> any action performed here is not persistent and does not change your config files.", "<b>Huom:</b> täällä tehdyt toimet eivät ole pysyviä, eikä niillä muuteta asetustiedostojasi."},
		{"Logging level", "Lokitustaso"},
		{"Transit tunnels limit", "Läpikulkutunneleiden enimmäismäärä"},
		{"Change", "Vaihda"},
		{"Change language", "Vaihda kieltä"},
		{"no transit tunnels currently built", "läpikulkutunneleita ei ole tällä hetkellä rakennettu"},
		{"SAM disabled", "SAM poistettu käytöstä"},
		{"no sessions currently running", "ei käynnissä olevia istuntoja"},
		{"SAM session not found", "SAM-istuntoa ei löydy"},
		{"SAM Session", "SAM Istunto"},
		{"Server Tunnels", "Palvelimen Tunnelit"},
		{"Client Forwards", "Asiakasohjaukset"},
		{"Server Forwards", "Serveriohjaukset"},
		{"Unknown page", "Tuntematon sivu"},
		{"Invalid token", "Virheellinen tunniste"},
		{"SUCCESS", "ONNISTUI"},
		{"Stream closed", "Yhteys suljettu"},
		{"Stream not found or already was closed", "Yhteyttä ei löytynyt tai se oli jo suljettuna"},
		{"Destination not found", "Kohdetta ei löydy"},
		{"StreamID can't be null", "StreamID ei voi olla tyhjä"},
		{"Return to destination page", "Palaa kohdesivulle"},
		{"You will be redirected in %d seconds", "Sinut ohjataan uudelleen %d sekunnissa"},
		{"LeaseSet expiration time updated", "LeaseSetin vanhentumisaika päivitetty"},
		{"LeaseSet is not found or already expired", "LeaseSetia ei löydy tai se on jo vanhentunut"},
		{"Transit tunnels count must not exceed %d", "Läpikulkutunnelien määrä ei saa ylittää %d"},
		{"Back to commands list", "Takaisin komentoluetteloon"},
		{"Register at reg.i2p", "Rekisteröidy osoitteessa reg.i2p"},
		{"Description", "Kuvaus"},
		{"A bit information about service on domain", "Vähän tietoa palvelusta verkkotunnuksella"},
		{"Submit", "Lähetä"},
		{"Domain can't end with .b32.i2p", "Verkkotunnus ei voi päättyä .b32.i2p"},
		{"Domain must end with .i2p", "Verkkotunnuksen täytyy päättyä .i2p"},
		{"Unknown command", "Tuntematon komento"},
		{"Command accepted", "Komento hyväksytty"},
		{"Proxy error", "Välityspalvelimen virhe"},
		{"Proxy info", "Välityspalvelimen tiedot"},
		{"Proxy error: Host not found", "Välityspalvelimen virhe: Palvelinta ei löydy"},
		{"Remote host not found in router's addressbook", "Etäpalvelinta ei löytynyt reitittimen osoitekirjasta"},
		{"You may try to find this host on jump services below", "Voit yrittää löytää tämän isännän alla olevilta jump-palveluilta"},
		{"Invalid request", "Virheellinen pyyntö"},
		{"Proxy unable to parse your request", "Välityspalvelin ei voi jäsentää pyyntöäsi"},
		{"Addresshelper is not supported", "Addresshelperia ei tueta"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Isäntä %s on jo <font color=red>reitittimen osoitekirjassa</font>. <b>Ole varovainen: tämän URL-osoitteen lähde saattaa olla haitallinen!</b> Klikkaa tästä päivittääksesi tiedot: <a href=\"%s%s%s&update=true\">Jatka</a>."},
		{"Addresshelper forced update rejected", "Addresshelperin pakotettu päivitys hylätty"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Lisätäksesi isännän <b>%s</b> reitittimen osoitekirjaan, klikkaa tästä: <a href=\"%s%s%s\">Jatka</a>."},
		{"Addresshelper request", "Addresshelper-pyyntö"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Isäntä %s lisätty reitittimen osoitekirjaan helperin kautta. Klikkaa tästä jatkaaksesi: <a href=\"%s\">Jatka</a>."},
		{"Addresshelper adding", "Addresshelper lisääminen"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Isäntä %s on jo <font color=red>reitittimen osoitekirjassa</font>. Klikkaa tästä päivittääksesi tiedot: <a href=\"%s%s%s&update=true\">Jatka</a>."},
		{"Addresshelper update", "Addresshelper päivitys"},
		{"Invalid request URI", "Virheellinen pyyntö URI"},
		{"Can't detect destination host from request", "Määränpään isäntää ei voitu tunnistaa pyynnöstä"},
		{"Outproxy failure", "Outproxy virhe"},
		{"Bad outproxy settings", "Virheelliset outproxy-asetukset"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Isäntä %s ei ole I2P-verkossa, mutta outproxy ei ole käytössä"},
		{"Unknown outproxy URL", "Tuntematon outproxy URL"},
		{"Cannot resolve upstream proxy", "Ei pystytä selvittämään yläproxy-palvelinta"},
		{"Hostname is too long", "Isäntänimi on liian pitkä"},
		{"Cannot connect to upstream SOCKS proxy", "Ei voida yhdistää SOCKS- välityspalvelimeen"},
		{"Cannot negotiate with SOCKS proxy", "Ei voida neuvotella SOCKS- välityspalvelimen kanssa"},
		{"CONNECT error", "YHDISTÄ error"},
		{"Failed to connect", "Yhteyden muodostaminen epäonnistui"},
		{"SOCKS proxy error", "SOCKS- välityspalvelinvirhe"},
		{"Failed to send request to upstream", "Pyyntöä ylätason palvelimelle ei voitu lähettää"},
		{"No reply from SOCKS proxy", "Ei vastausta SOCKS- välityspalvelimen kautta"},
		{"Cannot connect", "Yhdistäminen ei onnistunut"},
		{"HTTP out proxy not implemented", "HTTP-ulkovälityspalvelinta ei ole toteutettu"},
		{"Cannot connect to upstream HTTP proxy", "Yhteyttä HTTP-yläproxyyn ei saada"},
		{"Host is down", "Isäntä on alhaalla"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Yhteyden muodostaminen pyydettyyn isäntään ei onnistunut, se saattaa olla pois käytöstä. Yritä myöhemmin uudelleen."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d päivä", "%d päivää"}},
		{"%d hours", {"%d tunti", "%d tuntia"}},
		{"%d minutes", {"%d minuutti", "%d minuuttia"}},
		{"%d seconds", {"%d sekunti", "%d sekuntia"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
