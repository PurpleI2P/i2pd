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

// Italian localization file

namespace i2p
{
namespace i18n
{
namespace italian // language namespace
{
	// language name in lowercase
	static std::string language = "italian";

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
		{"building", "in costruzione"},
		{"failed", "fallito"},
		{"expiring", "in scadenza"},
		{"established", "stabilita"},
		{"unknown", "sconosciuto"},
		{"exploratory", "esplorativo"},
		{"Purple I2P Webconsole", "Terminale web Purple I2P"},
		{"<b>i2pd</b> webconsole", "Terminal web <b>i2pd</b>"},
		{"Main page", "Pagina principale"},
		{"Router commands", "Comandi router"},
		{"Local Destinations", "Destinazioni locali"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Tunnel"},
		{"Transit Tunnels", "Tunnel di transito"},
		{"Transports", "Trasporti"},
		{"I2P tunnels", "Tunnel I2P"},
		{"SAM sessions", "Sessioni SAM"},
		{"ERROR", "ERRORE"},
		{"OK", "OK"},
		{"Testing", "Testando"},
		{"Firewalled", "Protetto da firewall"},
		{"Unknown", "Sconosciuto"},
		{"Proxy", "Proxy"},
		{"Mesh", "Mesh"},
		{"Error", "Errore"},
		{"Clock skew", "Orologio disallineato"},
		{"Offline", "Disconnesso"},
		{"Symmetric NAT", "NAT simmetrico"},
		{"Uptime", "In funzione da"},
		{"Network status", "Stato della rete"},
		{"Network status v6", "Stato della rete v6"},
		{"Stopping in", "Arresto in"},
		{"Family", "Famiglia"},
		{"Tunnel creation success rate", "Percentuale di tunnel creati con successo"},
		{"Received", "Ricevuti"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Inviati"},
		{"Transit", "Transitati"},
		{"Data path", "Percorso dati"},
		{"Hidden content. Press on text to see.", "Contenuto nascosto. Premi sul testo per vedere."},
		{"Router Ident", "Identificativo del router"},
		{"Router Family", "Famiglia del router"},
		{"Router Caps", "Limiti del router"},
		{"Version", "Versione"},
		{"Our external address", "Il nostro indirizzo esterno"},
		{"supported", "supportato"},
		{"Routers", "Router"},
		{"Floodfills", "Floodfill"},
		{"Client Tunnels", "Tunnel client"},
		{"Services", "Servizi"},
		{"Enabled", "Abilitato"},
		{"Disabled", "Disabilitato"},
		{"Encrypted B33 address", "Indirizzo criptato B33"},
		{"Address registration line", "Linea di registrazione indirizzo"},
		{"Domain", "Dominio"},
		{"Generate", "Genera"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Nota:</b> la stringa risultante può essere utilizzata solo per registrare domini 2LD (example.i2p). Per registrare i sottodomini, si prega di utilizzare i2pd-tools."},
		{"Address", "Indirizzo"},
		{"Type", "Tipologia"},
		{"EncType", "Tipo di crittografia"},
		{"Inbound tunnels", "Tunnel in entrata"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Tunnel in uscita"},
		{"Tags", "Tag"},
		{"Incoming", "In entrata"},
		{"Outgoing", "In uscita"},
		{"Destination", "Destinazione"},
		{"Amount", "Quantità"},
		{"Incoming Tags", "Tag in entrata"},
		{"Tags sessions", "Sessioni dei tag"},
		{"Status", "Stato"},
		{"Local Destination", "Destinazione locale"},
		{"Streams", "Flussi"},
		{"Close stream", "Interrompi il flusso"},
		{"I2CP session not found", "Sessione I2CP non trovata"},
		{"I2CP is not enabled", "I2CP non è abilitato"},
		{"Invalid", "Invalido"},
		{"Store type", "Tipologia di archivio"},
		{"Expires", "Scade"},
		{"Non Expired Leases", "Lease non scaduti"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Data di fine"},
		{"not floodfill", "no floodfill"},
		{"Queue size", "Dimensione della coda"},
		{"Run peer test", "Esegui il test dei peer"},
		{"Decline transit tunnels", "Rifiuta tunnel di transito"},
		{"Accept transit tunnels", "Accetta tunnel di transito"},
		{"Cancel graceful shutdown", "Annulla l'interruzione controllata"},
		{"Start graceful shutdown", "Avvia l'interruzione controllata"},
		{"Force shutdown", "Forza l'arresto"},
		{"Reload external CSS styles", "Ricarica gli stili CSS esterni"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Nota:</b> qualsiasi azione effettuata qui non è persistente e non modifica i file di configurazione."},
		{"Logging level", "Livello di log"},
		{"Transit tunnels limit", "Limite di tunnel di transito"},
		{"Change", "Modifica"},
		{"Change language", "Modifica linguaggio"},
		{"no transit tunnels currently built", "Attualmente non ci sono tunnel di transito instaurati"},
		{"SAM disabled", "SAM disabilitato"},
		{"no sessions currently running", "Attualmente non ci sono sessioni attive"},
		{"SAM session not found", "Sessione SAM non trovata"},
		{"SAM Session", "Sessione SAM"},
		{"Server Tunnels", "Tunnel server"},
		{"Client Forwards", "Client di inoltro"},
		{"Server Forwards", "Server di inoltro"},
		{"Unknown page", "Pagina sconosciuta"},
		{"Invalid token", "Token non valido"},
		{"SUCCESS", "SUCCESSO"},
		{"Stream closed", "Flusso terminato"},
		{"Stream not found or already was closed", "Il flusso non è stato trovato oppure è già stato terminato"},
		{"Destination not found", "Destinazione non trovata"},
		{"StreamID can't be null", "Lo StreamID non può essere null"},
		{"Return to destination page", "Ritorna alla pagina di destinazione"},
		{"You will be redirected in 5 seconds", "Verrai reindirizzato in 5 secondi"},
		{"Transit tunnels count must not exceed 65535", "Il numero di tunnel di transito non può superare i 65535"},
		{"Back to commands list", "Ritorna alla lista dei comandi"},
		{"Register at reg.i2p", "Registra a reg.i2p"},
		{"Description", "Descrizione"},
		{"A bit information about service on domain", "Alcune informazioni riguardo il servizio sul dominio"},
		{"Submit", "Invia"},
		{"Domain can't end with .b32.i2p", "I domini non possono terminare con .b32.i2p"},
		{"Domain must end with .i2p", "I domini devono terminare con .i2p"},
		{"Such destination is not found", "Questa destinazione non è stata trovata"},
		{"Unknown command", "Comando sconosciuto"},
		{"Command accepted", "Comando accettato"},
		{"Proxy error", "Errore del proxy"},
		{"Proxy info", "Informazioni del proxy"},
		{"Proxy error: Host not found", "Errore del proxy: Host non trovato"},
		{"Remote host not found in router's addressbook", "L'host remoto non è stato trovato nella rubrica del router"},
		{"You may try to find this host on jump services below", "Si può provare a trovare questo host sui servizi di salto qui sotto"},
		{"Invalid request", "Richiesta non valida"},
		{"Proxy unable to parse your request", "Il proxy non è in grado di elaborare la tua richiesta"},
		{"addresshelper is not supported", "addresshelper non è supportato"},
		{"Host", "Host"},
		{"added to router's addressbook from helper", "aggiunto alla rubrica tramite l'helper"},
		{"Click here to proceed:", "Clicca qui per procedere:"},
		{"Continue", "Continua"},
		{"Addresshelper found", "Addresshelper trovato"},
		{"already in router's addressbook", "già presente nella rubrica del router"},
		{"Click here to update record:", "Clicca qui per aggiornare l'elemento:"},
		{"invalid request uri", "uri della richiesta non valido"},
		{"Can't detect destination host from request", "Impossibile determinare l'host di destinazione dalla richiesta"},
		{"Outproxy failure", "Fallimento del proxy di uscita"},
		{"bad outproxy settings", "impostazioni errate del proxy di uscita"},
		{"not inside I2P network, but outproxy is not enabled", "non all'interno della rete I2P, ma il proxy di uscita non è abilitato"},
		{"unknown outproxy url", "url del proxy di uscita sconosciuto"},
		{"cannot resolve upstream proxy", "impossibile identificare il flusso a monte del proxy"},
		{"hostname too long", "il nome dell'host è troppo lungo"},
		{"cannot connect to upstream socks proxy", "impossibile connettersi al flusso a monte del proxy socks"},
		{"Cannot negotiate with socks proxy", "Impossibile negoziare con il proxy socks"},
		{"CONNECT error", "Errore di connessione"},
		{"Failed to Connect", "Connessione fallita"},
		{"socks proxy error", "errore del proxy socks"},
		{"failed to send request to upstream", "invio della richiesta a monte non riuscito"},
		{"No Reply From socks proxy", "Nessuna risposta dal proxy socks"},
		{"cannot connect", "impossibile connettersi"},
		{"http out proxy not implemented", "proxy http di uscita non implementato"},
		{"cannot connect to upstream http proxy", "impossibile connettersi al proxy http a monte"},
		{"Host is down", "L'host è offline"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Impossibile creare la connessione all'host richiesto, probabilmente è offline. Riprova più tardi."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d giorno", "%d giorni"}},
		{"%d hours", {"%d ora", "%d ore"}},
		{"%d minutes", {"%d minuto", "%d minuti"}},
		{"%d seconds", {"%d secondo", "%d secondi"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
