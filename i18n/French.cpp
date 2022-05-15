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

// French localization file

namespace i2p
{
namespace i18n
{
namespace french // language namespace
{
	// language name in lowercase
	static std::string language = "french";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"KiB", "Kio"},
		{"MiB", "Mio"},
		{"GiB", "Gio"},
		{"building", "En construction"},
		{"failed", "echoué"},
		{"expiring", "expiré"},
		{"established", "établi"},
		{"unknown", "inconnu"},
		{"exploratory", "exploratoire"},
		{"<b>i2pd</b> webconsole", "Console web <b>i2pd</b>"},
		{"Main page", "Page principale"},
		{"Router commands", "Commandes du routeur"},
		{"Local Destinations", "Destinations locales"},
		{"Tunnels", "Tunnels"},
		{"Transit Tunnels", "Tunnels transitoires"},
		{"I2P tunnels", "Tunnels I2P"},
		{"SAM sessions", "Sessions SAM"},
		{"ERROR", "ERREUR"},
		{"OK", "OK"},
		{"Firewalled", "Derrière un pare-feu"},
		{"Error", "Erreur"},
		{"Offline", "Hors ligne"},
		{"Uptime", "Temps de fonctionnement"},
		{"Network status", "État du réseau"},
		{"Network status v6", "État du réseau v6"},
		{"Stopping in", "Arrêt dans"},
		{"Family", "Famille"},
		{"Tunnel creation success rate", "Taux de succès de création de tunnels"},
		{"Received", "Reçu"},
		{"KiB/s", "kio/s"},
		{"Sent", "Envoyé"},
		{"Transit", "Transit"},
		{"Hidden content. Press on text to see.", "Contenu caché. Cliquez sur le texte pour regarder."},
		{"Router Ident", "Identifiant du routeur"},
		{"Router Family", "Famille du routeur"},
		{"Version", "Version"},
		{"Our external address", "Notre adresse externe"},
		{"Client Tunnels", "Tunnels clients"},
		{"Services", "Services"},
		{"Enabled", "Activé"},
		{"Disabled", "Désactivé"},
		{"Encrypted B33 address", "Adresse B33 chiffrée"},
		{"Domain", "Domaine"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Note:</b> La chaîne résultante peut seulement être utilisée pour enregistrer les domaines 2LD (exemple.i2p). Pour enregistrer des sous-domaines, veuillez utiliser i2pd-tools."},
		{"Address", "Adresse"},
		{"ms", "ms"},
		{"Outbound tunnels", "Tunnels sortants"},
		{"Destination", "Destination"},
		{"Local Destination", "Destination locale"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days", {"jour", "jours"}},
		{"hours", {"heure", "heures"}},
		{"minutes", {"minute", "minutes"}},
		{"seconds", {"seconde", "secondes"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
