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
		{"Clock skew", "Orologio disallineato"},
		{"Offline", "Disconnesso"},
		{"Symmetric NAT", "NAT simmetrico"},
		{"Full cone NAT", "Cono completo NAT"},
		{"No Descriptors", "Nessun descrittore"},
		{"Uptime", "In funzione da"},
		{"Network status", "Stato della rete"},
		{"Network status v6", "Stato della rete v6"},
		{"Stopping in", "Arresto in"},
		{"Family", "Famiglia"},
		{"Tunnel creation success rate", "Percentuale di tunnel creati con successo"},
		{"Total tunnel creation success rate", "Percentuale di successo totale nella creazione del tunnel"},
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
		{"Expire LeaseSet", "Scadenza LeaseSet"},
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
		{"Such destination is not found", "Questa destinazione non è stata trovata"},
		{"I2CP session not found", "Sessione I2CP non trovata"},
		{"I2CP is not enabled", "I2CP non è abilitato"},
		{"Invalid", "Invalido"},
		{"Store type", "Tipologia di archivio"},
		{"Expires", "Scade"},
		{"Non Expired Leases", "Lease non scaduti"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Data di fine"},
		{"floodfill mode is disabled", "la modalità floodfill è disabilitata"},
		{"Queue size", "Dimensione della coda"},
		{"Run peer test", "Esegui il test dei peer"},
		{"Reload tunnels configuration", "Ricarica la configurazione dei tunnel"},
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
		{"You will be redirected in %d seconds", "Sarai reindirizzato tra %d secondi"},
		{"LeaseSet expiration time updated", "Tempo di scadenza LeaseSet aggiornato"},
		{"LeaseSet is not found or already expired", "LeaseSet non trovato o già scaduto"},
		{"Transit tunnels count must not exceed %d", "Il conteggio dei tunnel di transito non deve superare %d"},
		{"Back to commands list", "Ritorna alla lista dei comandi"},
		{"Register at reg.i2p", "Registra a reg.i2p"},
		{"Description", "Descrizione"},
		{"A bit information about service on domain", "Alcune informazioni riguardo il servizio sul dominio"},
		{"Submit", "Invia"},
		{"Domain can't end with .b32.i2p", "I domini non possono terminare con .b32.i2p"},
		{"Domain must end with .i2p", "I domini devono terminare con .i2p"},
		{"Unknown command", "Comando sconosciuto"},
		{"Command accepted", "Comando accettato"},
		{"Proxy error", "Errore del proxy"},
		{"Proxy info", "Informazioni del proxy"},
		{"Proxy error: Host not found", "Errore del proxy: Host non trovato"},
		{"Remote host not found in router's addressbook", "L'host remoto non è stato trovato nella rubrica del router"},
		{"You may try to find this host on jump services below", "Si può provare a trovare questo host sui servizi di salto qui sotto"},
		{"Invalid request", "Richiesta non valida"},
		{"Proxy unable to parse your request", "Il proxy non è in grado di elaborare la tua richiesta"},
		{"Addresshelper is not supported", "Addresshelper non è supportato"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "L'host %s è <font color=red>già nella rubrica del router</font>. <b>Attenzione: la fonte di questo URL potrebbe essere dannosa!</b> Fai clic qui per aggiornare il record: <a href=\"%s%s%s&update=true\">Continua</a>."},
		{"Addresshelper forced update rejected", "Aggiornamento forzato dell'helper degli indirizzi rifiutato"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Per aggiungere host <b>%s</b> nella rubrica del router, clicca qui: <a href=\"%s%s%s\">Continua</a>."},
		{"Addresshelper request", "Richiesta di indirizzo helper"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "L'host %s viene aggiunto alla rubrica del router dall'helper. Fai clic qui per procedere: <a href=\"%s\">Continua</a>."},
		{"Addresshelper adding", "Aggiunta di Addresshelper"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "L'host %s è <font color=red>già nella rubrica del router</font>. Clicca qui per aggiornare il record: <a href=\"%s%s%s&update=true\">Continua</a>."},
		{"Addresshelper update", "Aggiornamento dell'helper degli indirizzi"},
		{"Invalid request URI", "URI della richiesta non valido"},
		{"Can't detect destination host from request", "Impossibile determinare l'host di destinazione dalla richiesta"},
		{"Outproxy failure", "Fallimento del proxy di uscita"},
		{"Bad outproxy settings", "Impostazioni errate del proxy di uscita"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Host %s non all'interno della rete I2P, ma il proxy di uscita non è abilitato"},
		{"Unknown outproxy URL", "URL del proxy di uscita sconosciuto"},
		{"Cannot resolve upstream proxy", "Impossibile identificare il flusso a monte del proxy"},
		{"Hostname is too long", "Il nome dell'host è troppo lungo"},
		{"Cannot connect to upstream SOCKS proxy", "Impossibile connettersi al flusso a monte del proxy SOCKS"},
		{"Cannot negotiate with SOCKS proxy", "Impossibile negoziare con il proxy SOCKS"},
		{"CONNECT error", "Errore di connessione"},
		{"Failed to connect", "Connessione fallita"},
		{"SOCKS proxy error", "Errore del proxy SOCKS"},
		{"Failed to send request to upstream", "Invio della richiesta a monte non riuscito"},
		{"No reply from SOCKS proxy", "Nessuna risposta dal proxy SOCKS"},
		{"Cannot connect", "Impossibile connettersi"},
		{"HTTP out proxy not implemented", "Proxy HTTP di uscita non implementato"},
		{"Cannot connect to upstream HTTP proxy", "Impossibile connettersi al flusso a monte del proxy HTTP"},
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
