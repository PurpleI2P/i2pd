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

// Armenian localization file

namespace i2p
{
namespace i18n
{
namespace armenian // language namespace
{
	// language name in lowercase
	static std::string language = "armenian";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f ԿիԲ"},
		{"%.2f MiB", "%.2f ՄիԲ"},
		{"%.2f GiB", "%.2f ԳիԲ"},
		{"building", "կառուցվում է"},
		{"failed", "Անհաջող"},
		{"expiring", "Լրանում է"},
		{"established", "կարգավոյված է"},
		{"unknown", "անհայտ"},
		{"exploratory", "հետազոտոկան"},
		{"Purple I2P Webconsole", "Վեբ-կոնսոլ Purple I2P"},
		{"<b>i2pd</b> webconsole", "Վեբ-կոնսոլ <b>i2pd</b>"},
		{"Main page", "Գլխավոր էջ"},
		{"Router commands", "Երթուղիչի հրահանգներ"},
		{"Local Destinations", "Տեղական վերջնակետերը"},
		{"LeaseSets", "ԼիզՍեթեր"},
		{"Tunnels", "Թունելներ"},
		{"Transit Tunnels", "Տարանցիկ թունելներ"},
		{"Transports", "Տրանսպորտ"},
		{"I2P tunnels", "I2P թունելներ"},
		{"SAM sessions", "SAM նստաշրջաններ"},
		{"ERROR", "ՍԽԱԼ"},
		{"OK", "ԼԱՎ"},
		{"Testing", "Փորձարկում"},
		{"Firewalled", "Արգելափակված է դրսից"},
		{"Unknown", "Անհայտ"},
		{"Proxy", "Պրոկսի"},
		{"Mesh", "MESH-ցանց"},
		{"Clock skew", "Ոչ ճշգրիտ ժամանակ"},
		{"Offline", "Օֆլայն"},
		{"Symmetric NAT", "Սիմետրիկ NAT"},
		{"Full cone NAT", "Full cone NAT"},
		{"Uptime", "Առկայություն"},
		{"Network status", "Ցանցի կարգավիճակ"},
		{"Network status v6", "Ցանցի կարգավիճակ v6"},
		{"Stopping in", "Դադարում"},
		{"Family", "Խմբատեսակ"},
		{"Tunnel creation success rate", "Հաջողությամբ կառուցված թունելներ"},
		{"Received", "Ստացվել է"},
		{"%.2f KiB/s", "%.2f ԿիԲ/վ"},
		{"Sent", "Ուղարկվել է"},
		{"Transit", "Տարանցում"},
		{"Data path", "Տվյալների ուղին"},
		{"Hidden content. Press on text to see.", "Թաքցված բովանդակություն: Տեսնելու համար սեղմեկ տեքստին:"},
		{"Router Ident", "Երթուղիչի նույնականացուցիչ"},
		{"Router Family", "Երթուղիչի խումբը"},
		{"Router Caps", "Երթուղիչի հատկություններ"},
		{"Version", "Տարբերակ"},
		{"Our external address", "Մեր արտաքին հասցեն"},
		{"supported", "համատեղելի է"},
		{"Routers", "Երթուղիչներ"},
		{"Floodfills", "Floodfills-ներ"},
		{"Client Tunnels", "Oգտատիրական թունելներ"},
		{"Services", "Ծառայություններ"},
		{"Enabled", "Միացված է"},
		{"Disabled", "Անջատված է"},
		{"Encrypted B33 address", "Գաղտնագրված B33 հասցեներ"},
		{"Address registration line", "Հասցեի գրանցման տող"},
		{"Domain", "Տիրույթ"},
		{"Generate", "Գեներացնել"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b> Նշում. </b> արդյունքի տողը կարող է օգտագործվել միայն 2LD տիրույթներ գրանցելու համար (example.i2p): Ենթատիրույթներ գրանցելու համար խնդրում ենք օգտագործել i2pd-tools գործիքակազմը:"},
		{"Address", "Հասցե"},
		{"Type", "Տեսակը"},
		{"EncType", "Գաղտնագրի տեսակը"},
		{"Inbound tunnels", "Մուտքային թունելներ"},
		{"%dms", "%dմլվ"},
		{"Outbound tunnels", "Ելքային թունելներ"},
		{"Tags", "Թեգեր"},
		{"Incoming", "Մուտքային"},
		{"Outgoing", "ելքային"},
		{"Destination", "Նշանակման վայր"},
		{"Amount", "Քանակ"},
		{"Incoming Tags", "Մուտքային պիտակներ"},
		{"Tags sessions", "Նստաշրջանի պիտակներ"},
		{"Status", "Կարգավիճակ"},
		{"Local Destination", "Տեղական նշանակման կետ"},
		{"Streams", "Հոսքեր"},
		{"Close stream", "Փակել հոսքը"},
		{"I2CP session not found", "I2CP նստաշրջանը գոյություն չունի"},
		{"I2CP is not enabled", "I2CP միացված է"},
		{"Invalid", "Անվավեր"},
		{"Store type", "Պահեստավորման տեսակը"},
		{"Expires", "Սպառվում է"},
		{"Non Expired Leases", "Չսպառված Lease-եր"},
		{"Gateway", "Դարպաս"},
		{"TunnelID", "Թունելի ID"},
		{"EndDate", "Ավարտ"},
		{"Queue size", "Հերթի չափսը"},
		{"Run peer test", "Գործարկել փորձարկումը"},
		{"Decline transit tunnels", "Մերժել տարանցիկ թունելներ"},
		{"Accept transit tunnels", "Ընդունել տարանցիկ թունելներ"},
		{"Cancel graceful shutdown", "Չեղարկել սահուն անջատումը"},
		{"Start graceful shutdown", "Սկսել սահուն անջատումը"},
		{"Force shutdown", "Հարկադիր անջատում"},
		{"Reload external CSS styles", "Վերաբեռնեք CSS ոճաթերթը"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b> Նշում․ </b> այստեղ կատարված ցանկացած գործողություն մշտական ​​չէ և չի փոխում ձեր կազմաձևման ֆայլերը։"},
		{"Logging level", "Գրառման աստիճանը"},
		{"Transit tunnels limit", "Տարանցիկ թունելների սահմանափակում"},
		{"Change", "Փոփոխել"},
		{"Change language", "Փոփոխել լեզուն"},
		{"no transit tunnels currently built", "ընթացիկ կառուցված տարանցիկ թունելներ գոյություն չունեն"},
		{"SAM disabled", "SAM-ն անջատված է"},
		{"no sessions currently running", "ներկայումս գործող նստաշրջաններ գոյություն չունեն"},
		{"SAM session not found", "SAM նստաշրջան գոյություն չունի"},
		{"SAM Session", "SAM նստաշրջան"},
		{"Server Tunnels", "Սերվերային թունելներ"},
		{"Client Forwards", "Օգտատիրական փոխանցումներ"},
		{"Server Forwards", "Սերվերային փոխանցումներ"},
		{"Unknown page", "Անհայտ էջ"},
		{"Invalid token", "Սխալ տոկեն"},
		{"SUCCESS", "ՀԱՋՈՂՎԱԾ"},
		{"Stream closed", "Հոսքն անջատված է"},
		{"Stream not found or already was closed", "Հոսքը գոյություն չունի կամ արդեն ավարտված է"},
		{"Destination not found", "Հասցեի վայրը չի գտնվել"},
		{"StreamID can't be null", "StreamID-ն չի կարող լինել դատարկ"},
		{"Return to destination page", "Վերադառնալ նախորդ էջի հասցե"},
		{"Back to commands list", "Վերադառնալ հրահանգների ցուցակ"},
		{"Description", "Նկարագրություն"},
		{"A bit information about service on domain", "Մի փոքր տեղեկատվություն տիրոիյթում գտնվող ծառայության մասին"},
		{"Submit", "Ուղարկվել"},
		{"Domain can't end with .b32.i2p", "Տիրույթը չպետք է վերջանա .b32.i2p-ով"},
		{"Domain must end with .i2p", "Տիրույթը պետք է վերջանա .i2p-ով"},
		{"Such destination is not found", "Այդիպսի հասցե գոյություն չունի"},
		{"Unknown command", "Անհայտ հրահանգ"},
		{"Command accepted", "Հրարահանգն ընդունված է"},
		{"Proxy error", "Պրոկսի սխալ"},
		{"Proxy info", "Պրոկսի տեղեկություն"},
		{"Proxy error: Host not found", "Պրոկսի սխալ՝ նման հոսթ գոյություն չունի"},
		{"Remote host not found in router's addressbook", "Դեպի հոսթ կատարված հարցումը գոյություն չունի երթուղիչի հասցեագրքում"},
		{"You may try to find this host on jump services below", "Ստորև Դուք կարող եք գտնել այս հոսթը jump ծառայությունների միջոցով"},
		{"Invalid request", "Սխալ հարցում"},
		{"Proxy unable to parse your request", "Պրոկսին չի կարող հասկանալ Ձեր հարցումը"},
		{"Invalid request URI", "Սխալ ձևավորված URI հարցում"},
		{"Can't detect destination host from request", "Չհաջողվեց հայնտաբերեկ վայրի հասցեն նշված հարցմամբ"},
		{"Outproxy failure", "Սխալ արտաքին պրոքսի"},
		{"Bad outproxy settings", "Սխալ արտաքին պրոկսի կարգավորումներ"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Հոսթ %s Հարցումը I2P ցանցից դուրս է, բայց արտաքին պրոքսին միացված չէ"},
		{"Unknown outproxy URL", "Արտաքին պրոքսիի անհայտ URL"},
		{"Cannot resolve upstream proxy", "Չհաջողվեց որոշել վերադաս պրոկսին"},
		{"Hostname is too long", "Հոսթի անունը չափազանց երկար է"},
		{"Cannot connect to upstream SOCKS proxy", "Չհաջողվեց միանալ վերադաս SOCKS պրոկսի սերվերին"},
		{"Cannot negotiate with SOCKS proxy", "Չհաջողվեց պայմանավորվել վերադաս SOCKS պրոկսիի հետ"},
		{"CONNECT error", "Սխալ CONNECT հարցում"},
		{"Failed to connect", "Միանալ չhաջողվեց"},
		{"SOCKS proxy error", "Սխալ SOCKS պրոկսի"},
		{"Failed to send request to upstream", "Չհաջողվեց հարցումն ուղարկել վերադաս պրոկսիին"},
		{"No reply from SOCKS proxy", "Բացակայում է պատասխանը SOCKS պրոկսի սերվերի կողմից"},
		{"Cannot connect", "Հնարավոր չե միանալ"},
		{"HTTP out proxy not implemented", "Արտաքին HTTP պրոկսին դեռ իրականացված չէ"},
		{"Cannot connect to upstream HTTP proxy", "Չհաջողվեց միանալ վերադաս HTTP պրոկսի սերվերին"},
		{"Host is down", "Հոսթն անհասանելի է"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Հոսթի հետ կապը հաստատել չհաջողվեց, հնարավոր է այն անջատված է, փորձեք միանալ քիչ ուշ:"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days",    {"%d օր", "%d օր"}},
		{"%d hours",   {"%d ժամ", "%d ժամ"}},
		{"%d minutes", {"%d րոպե", "%d րոպե"}},
		{"%d seconds", {"%d վարկյան", "%d վարկյան"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
