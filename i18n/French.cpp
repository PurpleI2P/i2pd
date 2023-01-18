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
		{"%.2f KiB", "%.2f Kio"},
		{"%.2f MiB", "%.2f Mio"},
		{"%.2f GiB", "%.2f Gio"},
		{"building", "En construction"},
		{"failed", "échoué"},
		{"expiring", "expiré"},
		{"established", "établi"},
		{"unknown", "inconnu"},
		{"exploratory", "exploratoire"},
		{"Purple I2P Webconsole", "Console web Purple I2P"},
		{"<b>i2pd</b> webconsole", "Console web <b>i2pd</b>"},
		{"Main page", "Page principale"},
		{"Router commands", "Commandes du routeur"},
		{"Local Destinations", "Destinations locales"},
		{"LeaseSets", "Jeu de baux"},
		{"Tunnels", "Tunnels"},
		{"Transit Tunnels", "Tunnels transitoires"},
		{"Transports", "Transports"},
		{"I2P tunnels", "Tunnels I2P"},
		{"SAM sessions", "Sessions SAM"},
		{"ERROR", "ERREUR"},
		{"OK", "OK"},
		{"Testing", "Test en cours"},
		{"Firewalled", "Derrière un pare-feu"},
		{"Unknown", "Inconnu"},
		{"Proxy", "Proxy"},
		{"Mesh", "Maillé"},
		{"Error", "Erreur"},
		{"Clock skew", "Horloge décalée"},
		{"Offline", "Hors ligne"},
		{"Symmetric NAT", "NAT symétrique"},
		{"Uptime", "Temps de fonctionnement"},
		{"Network status", "État du réseau"},
		{"Network status v6", "État du réseau v6"},
		{"Stopping in", "Arrêt dans"},
		{"Family", "Famille"},
		{"Tunnel creation success rate", "Taux de succès de création de tunnels"},
		{"Received", "Reçu"},
		{"%.2f KiB/s", "%.2f kio/s"},
		{"Sent", "Envoyé"},
		{"Transit", "Transité"},
		{"Data path", "Emplacement des données"},
		{"Hidden content. Press on text to see.", "Contenu caché. Cliquez sur le texte pour afficher."},
		{"Router Ident", "Identifiant du routeur"},
		{"Router Family", "Famille du routeur"},
		{"Router Caps", "Limiteurs du routeur"},
		{"Version", "Version"},
		{"Our external address", "Notre adresse externe"},
		{"supported", "supporté"},
		{"Routers", "Routeurs"},
		{"Client Tunnels", "Tunnels clients"},
		{"Services", "Services"},
		{"Enabled", "Activé"},
		{"Disabled", "Désactivé"},
		{"Encrypted B33 address", "Adresse B33 chiffrée"},
		{"Address registration line", "Ligne d'inscription de l'adresse"},
		{"Domain", "Domaine"},
		{"Generate", "Générer"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Note:</b> La chaîne résultante peut seulement être utilisée pour enregistrer les domaines 2LD (exemple.i2p). Pour enregistrer des sous-domaines, veuillez utiliser i2pd-tools."},
		{"Address", "Adresse"},
		{"Type", "Type"},
		{"Inbound tunnels", "Tunnels entrants"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Tunnels sortants"},
		{"Tags", "Balises"},
		{"Incoming", "Entrant"},
		{"Outgoing", "Sortant"},
		{"Destination", "Destination"},
		{"Amount", "Quantité"},
		{"Incoming Tags", "Balises entrantes"},
		{"Tags sessions", "Sessions des balises"},
		{"Status", "Statut"},
		{"Local Destination", "Destination locale"},
		{"Streams", "Flux"},
		{"Close stream", "Fermer le flux"},
		{"I2CP session not found", "Session I2CP introuvable"},
		{"I2CP is not enabled", "I2CP est désactivé"},
		{"Invalid", "Invalide"},
		{"Store type", "Type de stockage"},
		{"Expires", "Expire"},
		{"Non Expired Leases", "Baux non expirés"},
		{"Gateway", "Passerelle"},
		{"TunnelID", "ID du tunnel"},
		{"EndDate", "Date de fin"},
		{"Queue size", "Longueur de la file"},
		{"Run peer test", "Lancer test des pairs"},
		{"Decline transit tunnels", "Refuser les tunnels transitoires"},
		{"Accept transit tunnels", "Accepter les tunnels transitoires"},
		{"Cancel graceful shutdown", "Annuler l'arrêt gracieux"},
		{"Start graceful shutdown", "Démarrer l'arrêt gracieux"},
		{"Force shutdown", "Forcer l'arrêt"},
		{"Reload external CSS styles", "Rafraîchir les styles CSS externes"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Note:</b> Toute action effectuée ici n'est pas permanente et ne modifie pas vos fichiers de configuration."},
		{"Logging level", "Niveau de journalisation"},
		{"Transit tunnels limit", "Limite sur les tunnels transitoires"},
		{"Change", "Changer"},
		{"Change language", "Changer la langue"},
		{"no transit tunnels currently built", "aucun tunnel transitoire présentement établi"},
		{"SAM disabled", "SAM désactivé"},
		{"no sessions currently running", "aucune session présentement en cours"},
		{"SAM session not found", "session SAM introuvable"},
		{"SAM Session", "Session SAM"},
		{"Server Tunnels", "Tunnels serveurs"},
		{"Unknown page", "Page inconnue"},
		{"Invalid token", "Jeton invalide"},
		{"SUCCESS", "SUCCÈS"},
		{"Stream closed", "Flux fermé"},
		{"Stream not found or already was closed", "Flux introuvable ou déjà fermé"},
		{"Destination not found", "Destination introuvable"},
		{"StreamID can't be null", "StreamID ne peut pas être vide"},
		{"Return to destination page", "Retourner à la page de destination"},
		{"You will be redirected in 5 seconds", "Vous allez être redirigé dans cinq secondes"},
		{"Transit tunnels count must not exceed 65535", "Le nombre de tunnels transitoires ne doit pas dépasser 65535"},
		{"Back to commands list", "Retour à la liste des commandes"},
		{"Register at reg.i2p", "Inscription à reg.i2p"},
		{"Description", "Description"},
		{"A bit information about service on domain", "Un peu d'information à propos des services disponibles dans le domaine"},
		{"Submit", "Soumettre"},
		{"Domain can't end with .b32.i2p", "Le domaine ne peut pas terminer par .b32.i2p"},
		{"Domain must end with .i2p", "Le domaine doit terminer par .i2p"},
		{"Such destination is not found", "Cette destination est introuvable"},
		{"Unknown command", "Commande inconnue"},
		{"Command accepted", "Commande acceptée"},
		{"Proxy error", "Erreur de proxy"},
		{"Proxy info", "Information sur le proxy"},
		{"Proxy error: Host not found", "Erreur de proxy: Hôte introuvable"},
		{"Remote host not found in router's addressbook", "Hôte distant introuvable dans le carnet d'adresse du routeur"},
		{"You may try to find this host on jump services below", "Vous pouvez essayer de trouver cet hôte sur des services de redirection ci-dessous"},
		{"Invalid request", "Requête invalide"},
		{"Proxy unable to parse your request", "Proxy incapable de comprendre votre requête"},
		{"addresshelper is not supported", "Assistant d'adresse non supporté"},
		{"Host", "Hôte"},
		{"added to router's addressbook from helper", "Ajouté au carnet d'adresse du routeur par l'assistant"},
		{"Click here to proceed:", "Cliquez ici pour continuer:"},
		{"Continue", "Continuer"},
		{"Addresshelper found", "Assistant d'adresse trouvé"},
		{"already in router's addressbook", "déjà dans le carnet d'adresses du routeur"},
		{"Click here to update record:", "Cliquez ici pour mettre à jour le carnet d'adresse:"},
		{"invalid request uri", "uri de la requête invalide"},
		{"Can't detect destination host from request", "Impossible de détecter l'hôte de destination à partir de la requête"},
		{"Outproxy failure", "Échec de proxy de sortie"},
		{"bad outproxy settings", "Mauvaise configuration du proxy de sortie"},
		{"not inside I2P network, but outproxy is not enabled", "pas dans le réseau I2P, mais le proxy de sortie n'est pas activé"},
		{"unknown outproxy url", "URL du proxy de sortie inconnu"},
		{"cannot resolve upstream proxy", "impossible de résoudre l'adresse du proxy en amont"},
		{"hostname too long", "nom d'hôte trop long"},
		{"cannot connect to upstream socks proxy", "impossible de se connecter au proxy socks en amont"},
		{"Cannot negotiate with socks proxy", "Impossible de négocier avec le proxy socks"},
		{"CONNECT error", "Erreur de connexion"},
		{"Failed to Connect", "Échec de connexion"},
		{"socks proxy error", "Erreur de proxy socks"},
		{"failed to send request to upstream", "Erreur lors de l'envoie de la requête en amont"},
		{"No Reply From socks proxy", "Pas de réponse du proxy socks"},
		{"cannot connect", "impossible de connecter"},
		{"http out proxy not implemented", "Proxy de sortie HTTP non implémenté"},
		{"cannot connect to upstream http proxy", "impossible de se connecter au proxy HTTP en amont"},
		{"Host is down", "Hôte hors service"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Impossible d'établir une connexion avec l'hôte, il est peut-être hors service. Veuillez réessayer plus tard."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d jour", "%d jours"}},
		{"%d hours", {"%d heure", "%d heures"}},
		{"%d minutes", {"%d minute", "%d minutes"}},
		{"%d seconds", {"%d seconde", "%d secondes"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
