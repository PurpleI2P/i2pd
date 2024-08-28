/*
* Copyright (c) 2022-2024, The PurpleI2P Project
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
		{"Clock skew", "Décalage de l'horloge"},
		{"Offline", "Hors ligne"},
		{"Symmetric NAT", "NAT symétrique"},
		{"Full cone NAT", "NAT à cône complet"},
		{"No Descriptors", "Aucuns Descripteurs"},
		{"Uptime", "Temps de fonctionnement"},
		{"Network status", "État du réseau"},
		{"Network status v6", "État du réseau v6"},
		{"Stopping in", "Arrêt dans"},
		{"Family", "Famille"},
		{"Tunnel creation success rate", "Taux de création de tunnel réussie"},
		{"Total tunnel creation success rate", "Taux total de création de tunnel réussie"},
		{"Received", "Reçu"},
		{"%.2f KiB/s", "%.2f Kio/s"},
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
		{"Floodfills", "Remplisseurs"},
		{"Client Tunnels", "Tunnels clients"},
		{"Services", "Services"},
		{"Enabled", "Activé"},
		{"Disabled", "Désactivé"},
		{"Encrypted B33 address", "Adresse B33 chiffrée"},
		{"Address registration line", "Ligne d'inscription de l'adresse"},
		{"Domain", "Domaine"},
		{"Generate", "Générer"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Note :</b> La chaîne résultante peut seulement être utilisée pour enregistrer les domaines 2LD (exemple.i2p). Pour enregistrer des sous-domaines, veuillez utiliser i2pd-tools."},
		{"Address", "Adresse"},
		{"Type", "Type"},
		{"EncType", "EncType"},
		{"Expire LeaseSet", "Expirer le jeu de baux"},
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
		{"Such destination is not found", "Cette destination est introuvable"},
		{"I2CP session not found", "Session I2CP introuvable"},
		{"I2CP is not enabled", "I2CP est désactivé"},
		{"Invalid", "Invalide"},
		{"Store type", "Type de stockage"},
		{"Expires", "Expire"},
		{"Non Expired Leases", "Baux non expirés"},
		{"Gateway", "Passerelle"},
		{"TunnelID", "ID du tunnel"},
		{"EndDate", "Date de fin"},
		{"floodfill mode is disabled", "le mode de remplissage est désactivé"},
		{"Queue size", "Longueur de la file"},
		{"Run peer test", "Lancer test des pairs"},
		{"Reload tunnels configuration", "Recharger la configuration des tunnels"},
		{"Decline transit tunnels", "Refuser les tunnels transitoires"},
		{"Accept transit tunnels", "Accepter les tunnels transitoires"},
		{"Cancel graceful shutdown", "Annuler l'arrêt gracieux"},
		{"Start graceful shutdown", "Démarrer l'arrêt gracieux"},
		{"Force shutdown", "Forcer l'arrêt"},
		{"Reload external CSS styles", "Rafraîchir les styles CSS externes"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Note :</b> Toute action effectuée ici n'est pas permanente et ne modifie pas vos fichiers de configuration."},
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
		{"Client Forwards", "Transmission du client"},
		{"Server Forwards", "Transmission du serveur"},
		{"Unknown page", "Page inconnue"},
		{"Invalid token", "Jeton invalide"},
		{"SUCCESS", "SUCCÈS"},
		{"Stream closed", "Flux fermé"},
		{"Stream not found or already was closed", "Flux introuvable ou déjà fermé"},
		{"Destination not found", "Destination introuvable"},
		{"StreamID can't be null", "StreamID ne peut pas être vide"},
		{"Return to destination page", "Retourner à la page de destination"},
		{"You will be redirected in %d seconds", "Vous serez redirigé dans %d secondes"},
		{"LeaseSet expiration time updated", "Temps d'expiration du jeu de baux mis à jour"},
		{"LeaseSet is not found or already expired", "Le jeu de baux est introuvable ou a déjà expiré"},
		{"Transit tunnels count must not exceed %d", "Le nombre de tunnels de transit ne doit pas excéder %d"},
		{"Back to commands list", "Retour à la liste des commandes"},
		{"Register at reg.i2p", "Inscription à reg.i2p"},
		{"Description", "Description"},
		{"A bit information about service on domain", "Un peu d'information à propos des services disponibles dans le domaine"},
		{"Submit", "Soumettre"},
		{"Domain can't end with .b32.i2p", "Le domaine ne peut pas terminer par .b32.i2p"},
		{"Domain must end with .i2p", "Le domaine doit terminer par .i2p"},
		{"Unknown command", "Commande inconnue"},
		{"Command accepted", "Commande acceptée"},
		{"Proxy error", "Erreur de proxy"},
		{"Proxy info", "Information sur le proxy"},
		{"Proxy error: Host not found", "Erreur de proxy : Hôte introuvable"},
		{"Remote host not found in router's addressbook", "Hôte distant introuvable dans le carnet d'adresse du routeur"},
		{"You may try to find this host on jump services below", "Vous pouvez essayer de trouver cet hôte sur des services de redirection ci-dessous"},
		{"Invalid request", "Requête invalide"},
		{"Proxy unable to parse your request", "Proxy incapable de comprendre votre requête"},
		{"Addresshelper is not supported", "Assistant d'adresse non supporté"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "L'hôte %s est <font color=red>déjà dans le carnet d'adresses du routeur</font>. <b>Attention : la source de cette URL peut être nuisible !</b> Cliquez ici pour mettre à jour l'enregistrement : <a href=\"%s%s%s&update=true\">Continuer</a>."},
		{"Addresshelper forced update rejected", "Mise à jour forcée des assistants d'adresses rejetée"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Pour ajouter l'hôte <b>%s</b> au carnet d'adresses du routeur, cliquez ici : <a href=\"%s%s%s\">Continuer</a>."},
		{"Addresshelper request", "Demande à l'assistant d'adresse"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "L'hôte %s a été ajouté au carnet d'adresses du routeur depuis l'assistant. Cliquez ici pour continuer : <a href=\"%s\">Continuer</a>."},
		{"Addresshelper adding", "Ajout de l'assistant d'adresse"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "L'hôte %s est <font color=red>déjà dans le carnet d'adresses du routeur</font>. Cliquez ici pour mettre à jour le dossier : <a href=\"%s%s%s&update=true\">Continuer</a>."},
		{"Addresshelper update", "Mise à jour de l'assistant d'adresse"},
		{"Invalid request URI", "URI de la requête invalide"},
		{"Can't detect destination host from request", "Impossible de détecter l'hôte de destination à partir de la requête"},
		{"Outproxy failure", "Échec de proxy de sortie"},
		{"Bad outproxy settings", "Mauvaise configuration du proxy de sortie"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Hôte %s pas dans le réseau I2P, mais le proxy de sortie n'est pas activé"},
		{"Unknown outproxy URL", "URL du proxy de sortie inconnu"},
		{"Cannot resolve upstream proxy", "Impossible de résoudre l'adresse du proxy en amont"},
		{"Hostname is too long", "Nom d'hôte trop long"},
		{"Cannot connect to upstream SOCKS proxy", "Impossible de se connecter au proxy SOCKS en amont"},
		{"Cannot negotiate with SOCKS proxy", "Impossible de négocier avec le proxy SOCKS"},
		{"CONNECT error", "Erreur de connexion"},
		{"Failed to connect", "Échec de connexion"},
		{"SOCKS proxy error", "Erreur de proxy SOCKS"},
		{"Failed to send request to upstream", "Erreur lors de l'envoie de la requête en amont"},
		{"No reply from SOCKS proxy", "Pas de réponse du proxy SOCKS"},
		{"Cannot connect", "Impossible de connecter"},
		{"HTTP out proxy not implemented", "Proxy de sortie HTTP non implémenté"},
		{"Cannot connect to upstream HTTP proxy", "Impossible de se connecter au proxy HTTP en amont"},
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
