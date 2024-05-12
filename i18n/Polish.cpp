/*
* Copyright (c) 2023-2024, The PurpleI2P Project
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

// Polish localization file

namespace i2p
{
namespace i18n
{
namespace polish // language namespace
{
	// language name in lowercase
	static std::string language = "polish";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return (n == 1 ? 0 : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2);
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "Kompilowanie"},
		{"failed", "nieudane"},
		{"expiring", "wygasający"},
		{"established", "ustanowiony"},
		{"unknown", "nieznany"},
		{"exploratory", "eksploracyjny"},
		{"Purple I2P Webconsole", "Konsola webowa Purple I2P"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> konsola webowa"},
		{"Main page", "Strona główna"},
		{"Router commands", "Komendy routera"},
		{"Local Destinations", "Lokalne miejsca docelowe"},
		{"LeaseSets", "ZestawyNajmu"},
		{"Tunnels", "Tunele"},
		{"Transit Tunnels", "Tunele Tranzytu"},
		{"Transports", "Transportery"},
		{"I2P tunnels", "Tunele I2P"},
		{"SAM sessions", "Sesje SAM"},
		{"ERROR", "BŁĄD"},
		{"OK", "Ok"},
		{"Testing", "Testowanie"},
		{"Firewalled", "Za zaporą sieciową"},
		{"Unknown", "Nieznany"},
		{"Proxy", "Proxy"},
		{"Mesh", "Sieć"},
		{"Clock skew", "Przesunięcie czasu"},
		{"Offline", "Offline"},
		{"Symmetric NAT", "Symetryczny NAT"},
		{"Full cone NAT", "Pełny stożek NAT"},
		{"No Descriptors", "Brak deskryptorów"},
		{"Uptime", "Czas pracy"},
		{"Network status", "Stan sieci"},
		{"Network status v6", "Stan sieci v6"},
		{"Stopping in", "Zatrzymywanie za"},
		{"Family", "Rodzina"},
		{"Tunnel creation success rate", "Wskaźnik sukcesu tworzenia tunelu"},
		{"Total tunnel creation success rate", "Całkowity wskaźnik sukcesu tworzenia tunelu"},
		{"Received", "Odebrano"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Wysłane"},
		{"Transit", "Tranzyt"},
		{"Data path", "Ścieżka do danych"},
		{"Hidden content. Press on text to see.", "Ukryta zawartość. Naciśnij tekst, aby zobaczyć."},
		{"Router Ident", "Identyfikator routera"},
		{"Router Family", "Rodzina routera"},
		{"Router Caps", "Możliwości routera"},
		{"Version", "Wersja"},
		{"Our external address", "Nasz zewnętrzny adres"},
		{"supported", "wspierane"},
		{"Routers", "Routery"},
		{"Floodfills", "Floodfille"},
		{"Client Tunnels", "Tunele Klienta"},
		{"Services", "Usługi"},
		{"Enabled", "Aktywny"},
		{"Disabled", "Wyłączony"},
		{"Encrypted B33 address", "Zaszyfrowany adres B33"},
		{"Address registration line", "Linia rejestracji adresu"},
		{"Domain", "Domena"},
		{"Generate", "Generuj"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Uwaga:</b> wynik string może być używany tylko do rejestracji domen 2LD (przykład.i2p). Do rejestracji subdomen należy użyć narzędzi i2pd."},
		{"Address", "Adres"},
		{"Type", "Typ"},
		{"EncType", "TypEnkrypcji"},
		{"Expire LeaseSet", "Wygaśnij LeaseSet"},
		{"Inbound tunnels", "Tunele przychodzące"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Tunele wychodzące"},
		{"Tags", "Tagi"},
		{"Incoming", "Przychodzące"},
		{"Outgoing", "Wychodzące"},
		{"Destination", "Miejsce docelowe"},
		{"Amount", "Ilość"},
		{"Incoming Tags", "Przychodzące tagi"},
		{"Tags sessions", "Sesje tagów"},
		{"Status", "Status"},
		{"Local Destination", "Lokalne miejsce docelowe"},
		{"Streams", "Strumienie"},
		{"Close stream", "Zamknij strumień"},
		{"Such destination is not found", "Nie znaleziono takiego miejsca docelowego"},
		{"I2CP session not found", "Sesja I2CP nie została znaleziona"},
		{"I2CP is not enabled", "I2CP nie jest włączone"},
		{"Invalid", "Niepoprawny"},
		{"Store type", "Rodzaj przechowywania"},
		{"Expires", "Wygasa za"},
		{"Non Expired Leases", "Leasingi niewygasłe"},
		{"Gateway", "Brama"},
		{"TunnelID", "IDTunelu"},
		{"EndDate", "DataZakończenia"},
		{"floodfill mode is disabled", "tryb floodfill jest wyłączony"},
		{"Queue size", "Wielkość kolejki"},
		{"Run peer test", "Wykonaj test peer"},
		{"Reload tunnels configuration", "Załaduj ponownie konfigurację tuneli"},
		{"Decline transit tunnels", "Odrzuć tunele tranzytowe"},
		{"Accept transit tunnels", "Akceptuj tunele tranzytowe"},
		{"Cancel graceful shutdown", "Anuluj łagodne wyłączenie"},
		{"Start graceful shutdown", "Rozpocznij łagodne wyłączenie"},
		{"Force shutdown", "Wymuś wyłączenie"},
		{"Reload external CSS styles", "Odśwież zewnętrzne style CSS"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Uwaga:</b> każda akcja wykonana tutaj nie jest trwała i nie zmienia Twoich plików konfiguracyjnych."},
		{"Logging level", "Poziom logowania"},
		{"Transit tunnels limit", "Limit tuneli tranzytowych"},
		{"Change", "Zmień"},
		{"Change language", "Zmień język"},
		{"no transit tunnels currently built", "brak obecnie zbudowanych tuneli tranzytowych"},
		{"SAM disabled", "SAM wyłączony"},
		{"no sessions currently running", "brak aktualnie uruchomionych sesji"},
		{"SAM session not found", "Sesja SAM nie została znaleziona"},
		{"SAM Session", "Sesja SAM"},
		{"Server Tunnels", "Tunele Serwera"},
		{"Client Forwards", "Przekierowania Klienta"},
		{"Server Forwards", "Przekierowania Serwera"},
		{"Unknown page", "Nieznana strona"},
		{"Invalid token", "Nieprawidłowy token"},
		{"SUCCESS", "SUKCES"},
		{"Stream closed", "Strumień zamknięty"},
		{"Stream not found or already was closed", "Strumień nie został znaleziony lub został już zamknięty"},
		{"Destination not found", "Nie znaleziono punktu docelowego"},
		{"StreamID can't be null", "StreamID nie może być null"},
		{"Return to destination page", "Wróć do strony miejsca docelowego"},
		{"You will be redirected in %d seconds", "Zostaniesz prekierowany za %d sekund"},
		{"LeaseSet expiration time updated", "Zaktualizowano czas wygaśnięcia LeaseSet"},
		{"LeaseSet is not found or already expired", "LeaseSet nie został znaleziony lub już wygasł"},
		{"Transit tunnels count must not exceed %d", "Liczba tuneli tranzytowych nie może przekraczać %d"},
		{"Back to commands list", "Powrót do listy poleceń"},
		{"Register at reg.i2p", "Zarejestruj się na reg.i2p"},
		{"Description", "Opis"},
		{"A bit information about service on domain", "Trochę informacji o usłudze w domenie"},
		{"Submit", "Zatwierdź"},
		{"Domain can't end with .b32.i2p", "Domena nie może kończyć się na .b32.i2p"},
		{"Domain must end with .i2p", "Domena musi kończyć się na .i2p"},
		{"Unknown command", "Nieznana komenda"},
		{"Command accepted", "Polecenie zaakceptowane"},
		{"Proxy error", "Błąd serwera proxy"},
		{"Proxy info", "Informacje o proxy"},
		{"Proxy error: Host not found", "Błąd proxy: Nie znaleziono hosta"},
		{"Remote host not found in router's addressbook", "Nie znaleziono zdalnego hosta w książce adresowej routera"},
		{"You may try to find this host on jump services below", "Możesz znaleźć tego hosta na poniższych usługach skoku"},
		{"Invalid request", "Nieprawidłowe żądanie"},
		{"Proxy unable to parse your request", "Serwer proxy nie może przetworzyć Twojego żądania"},
		{"Addresshelper is not supported", "Adresshelper nie jest obsługiwany"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Host %s <font color=red>jest już w książce adresowej routera</font>. <b>Uważaj: źródło tego adresu URL może być szkodliwe!</b> Kliknij tutaj, aby zaktualizować rekord: <a href=\"%s%s%s&update=true\">Kontynuuj</a>."},
		{"Addresshelper forced update rejected", "Wymuszona aktualizacja Addreshelper odrzucona"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Aby dodać host <b>%s</b> w książce adresowej routera, kliknij tutaj: <a href=\"%s%s%s\">Kontynuuj</a>."},
		{"Addresshelper request", "Prośba Addresshelper"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Host %s dodany do książki adresowej routera od pomocnika. Kliknij tutaj, aby kontynuować: <a href=\"%s\">Kontynuuj</a>."},
		{"Addresshelper adding", "Dodawanie Addresshelper"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Host %s jest <font color=red>już w książce adresowej routera</font>. Kliknij tutaj, aby zaktualizować rekord: <a href=\"%s%s%s&update=true\">Kontynuuj</a>."},
		{"Addresshelper update", "Aktualizacja Adresshelper"},
		{"Invalid request URI", "Nieprawidłowe URI żądania"},
		{"Can't detect destination host from request", "Nie można wykryć hosta docelowego z żądania"},
		{"Outproxy failure", "Błąd proxy wyjściowego"},
		{"Bad outproxy settings", "Błędne ustawienia proxy wyjściowych"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Host %s nie jest wewnątrz sieci I2P, a proxy wyjściowe nie jest włączone"},
		{"Unknown outproxy URL", "Nieznany adres URL proxy wyjściowego"},
		{"Cannot resolve upstream proxy", "Nie można rozwiązać serwera proxy upstream"},
		{"Hostname is too long", "Nazwa hosta jest zbyt długa"},
		{"Cannot connect to upstream SOCKS proxy", "Nie można połączyć się z proxy SOCKS upstream"},
		{"Cannot negotiate with SOCKS proxy", "Nie można negocjować z proxy SOCKS"},
		{"CONNECT error", "Błąd POŁĄCZENIE"},
		{"Failed to connect", "Nie udało się połączyć"},
		{"SOCKS proxy error", "Błąd proxy SOCKS"},
		{"Failed to send request to upstream", "Nie udało się wysłać żądania do upstream"},
		{"No reply from SOCKS proxy", "Brak odpowiedzi od serwera proxy SOCKS"},
		{"Cannot connect", "Nie można się połączyć"},
		{"HTTP out proxy not implemented", "Serwer wyjściowy proxy HTTP nie został zaimplementowany"},
		{"Cannot connect to upstream HTTP proxy", "Nie można połączyć się z proxy HTTP upstream"},
		{"Host is down", "Host jest niedostępny"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Nie można utworzyć połączenia z żądanym hostem, może być wyłączony. Spróbuj ponownie później."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d dzień", "%d dni", "%d dni", "%d dni"}},
		{"%d hours", {"%d godzina", "%d godziny", "%d godzin", "%d godzin"}},
		{"%d minutes", {"%d minuta", "%d minuty", "%d minut", "%d minut"}},
		{"%d seconds", {"%d sekunda", "%d sekundy", "%d sekund", "%d sekund"}},
		{"", {"", "", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
