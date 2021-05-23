#include <map>
#include <vector>
#include <string>

// Russian localization file

namespace i2p {
namespace i18n {
namespace russian { // language

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	int plural (int n) {
		return n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2;
	}

	static std::map<std::string, std::string> strings
	{
		// HTTP Proxy
		{"Proxy error", "Ошибка прокси"},
		{"Proxy info", "Информация прокси"},
		{"Proxy error: Host not found", "Ошибка прокси: Адрес не найден"},
		{"Remote host not found in router's addressbook", "Запрошенный адрес не найден в адресной книге роутера"},
		{"You may try to find this host on jump services below", "Вы можете попробовать найти адрес на джамп сервисах ниже"},
		{"Invalid request", "Некорректный запрос"},
		{"Proxy unable to parse your request", "Прокси не может разобрать ваш запрос"},
		{"addresshelper is not supported", "addresshelper не поддерживается"},
		{"Host", "Адрес"},
		{"added to router's addressbook from helper", "добавлен в адресную книгу роутера через хелпер"},
		{"already in router's addressbook", "уже а адресной книге роутера"},
		{"Click", "Нажмите"},
		{"here", "здесь"},
		{"to proceed", "чтобы продолжить"},
		{"to update record", "чтобы обновить запись"},
		{"Addresshelper found", "Найден addresshelper"},
		{"invalid request uri", "некорректный URI запроса"},
		{"Can't detect destination host from request", "Не удалось определить адрес назначения из запроса"},
		{"Outproxy failure", "Ошибка внешнего прокси"},
		{"bad outproxy settings", "некорректные настройки внешнего прокси"},
		{"not inside I2P network, but outproxy is not enabled", "не в I2P сети, но внешний прокси не включен"},
		{"unknown outproxy url", "неизвестный URL внешнего прокси"},
		{"cannot resolve upstream proxy", "не удается определить внешний прокси"},
		{"hostname too long", "имя хоста слишком длинное"},
		{"cannot connect to upstream socks proxy", "не удается подключиться к вышестоящему SOCKS прокси"},
		{"Cannot negotiate with socks proxy", "Не удается договориться с вышестоящим SOCKS прокси"},
		{"CONNECT error", "Ошибка CONNECT запроса"},
		{"Failed to Connect", "Не удалось подключиться"},
		{"socks proxy error", "ошибка SOCKS прокси"},
		{"failed to send request to upstream", "не удалось отправить запрос вышестоящему прокси"},
		{"No Reply From socks proxy", "Нет ответа от SOCKS прокси сервера"},
		{"cannot connect", "не удалось подключиться"},
		{"http out proxy not implemented", "поддержка внешнего HTTP прокси сервера не реализована"},
		{"cannot connect to upstream http proxy", "не удалось подключиться к вышестоящему HTTP прокси серверу"},
		{"Host is down", "Адрес недоступен"},
		{"Can't create connection to requested host, it may be down. Please try again later.",
			"Не удалось установить соединение к запрошенному адресу, возможно он не в сети. Попробуйте повторить запрос позже."},

		// Webconsole //
		// cssStyles
		{"Disabled", "Выключено"},
		{"Enabled", "Включено"},
		// ShowTraffic
		{"KiB", "КиБ"},
		{"MiB", "МиБ"},
		{"GiB", "ГиБ"},
		// ShowTunnelDetails
		{"building", "строится"},
		{"failed", "неудачный"},
		{"expiring", "истекает"},
		{"established", "работает"},
		{"exploratory", "исследовательский"},
		{"unknown", "неизвестно"},
		{"<b>i2pd</b> webconsole", "Веб-консоль <b>i2pd</b>"},
		// ShowPageHead
		{"Main page", "Главная"},
		{"Router commands", "Команды роутера"},
		{"Local destinations", "Локальные назнач."},
		{"LeaseSets", "Лизсеты"},
		{"Tunnels", "Туннели"},
		{"Transit tunnels", "Транзит. туннели"},
		{"Transports", "Транспорты"},
		{"I2P tunnels", "I2P туннели"},
		{"SAM sessions", "SAM сессии"},
		// Network Status
		{"OK", "OK"},
		{"Testing", "Тестирование"},
		{"Firewalled", "Файрвол"},
		{"Unknown", "Неизвестно"},
		{"Proxy", "Прокси"},
		{"Mesh", "MESH-сеть"},
		{"Error", "Ошибка"},
		{"Clock skew", "Не точное время"},
		{"Offline", "Оффлайн"},
		{"Symmetric NAT", "Симметричный NAT"},
		// Status
		{"Uptime", "В сети"},
		{"Network status", "Сетевой статус"},
		{"Network status v6", "Сетевой статус v6"},
		{"Stopping in", "Остановка через"},
		{"Family", "Семейство"},
		{"Tunnel creation success rate", "Успешно построенных туннелей"},
		{"Received", "Получено"},
		{"Sent", "Отправлено"},
		{"Transit", "Транзит"},
		{"KiB/s", "КиБ/с"},
		{"Data path", "Путь к данным"},
		{"Hidden content. Press on text to see.", "Скрытый контент. Нажмите на текст чтобы отобразить."},
		{"Router Ident", "Идентификатор роутера"},
		{"Router Family", "Семейство роутера"},
		{"Router Caps", "Флаги роутера"},
		{"Version", "Версия"},
		{"Our external address", "Наш внешний адрес"},
		{"supported", "поддерживается"},
		{"Routers", "Роутеры"},
		{"Floodfills", "Флудфилы"},
		{"LeaseSets", "Лизсеты"},
		{"Client Tunnels", "Клиентские туннели"},
		{"Transit Tunnels", "Транзитные туннели"},
		{"Services", "Сервисы"},
		// ShowLocalDestinations
		{"Local Destinations", "Локальные назначения"},
		// ShowLeaseSetDestination
		{"Encrypted B33 address", "Шифрованные B33 адреса"},
		{"Address registration line", "Строка регистрации адреса"},
		{"Domain", "Домен"},
		{"Generate", "Сгенерировать"},
		{"Address", "Адрес"},
		{"Type", "Тип"},
		{"EncType", "ТипШифр"},
		{"Inbound tunnels", "Входящие туннели"},
		{"Outbound tunnels", "Исходящие туннели"},
		{"ms", "мс"}, // milliseconds
		{"Tags", "Теги"},
		{"Incoming", "Входящие"},
		{"Outgoing", "Исходящие"},
		{"Destination", "Назначение"},
		{"Amount", "Количество"},
		{"Incoming Tags", "Входящие Теги"},
		{"Tags sessions", "Сессии Тегов"},
		{"Status", "Статус"},
		// ShowLocalDestination
		{"Local Destination", "Локальное назначение"},
		{"Streams", "Стримы"},
		{"Close stream", "Закрыть стрим"},
		// ShowI2CPLocalDestination
		{"I2CP session not found", "I2CP сессия не найдена"},
		{"I2CP is not enabled", "I2CP не включен"},
		// ShowLeasesSets
		{"Invalid", "Некорректный"},
		{"Store type", "Тип хранилища"},
		{"Expires", "Истекает"},
		{"Non Expired Leases", "Не истекшие Lease-ы"},
		{"Gateway", "Шлюз"},
		{"TunnelID", "ID туннеля"},
		{"EndDate", "Заканчивается"},
		{"not floodfill", "не флудфил"},
		// ShowTunnels
		{"Queue size", "Размер очереди"},
		// ShowCommands
		{"Run peer test", "Запустить тестирование"},
		{"Decline transit tunnels", "Отклонять транзитные туннели"},
		{"Accept transit tunnels", "Принимать транзитные туннели"},
		{"Cancel graceful shutdown", "Отменить плавную остановку"},
		{"Start graceful shutdown", "Запустить плавную остановку"},
		{"Force shutdown", "Принудительная остановка"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.",
			"<b>Примечание:</b> любое действие произведенное здесь не является постоянным и не изменяет ваши конфигурационные файлы."},
		{"Logging level", "Уровень логирования"},
		{"Transit tunnels limit", "Лимит транзитных туннелей"},
		{"Change", "Изменить"},
		// ShowTransitTunnels
		{"no transit tunnels currently built", "нет построенных транзитных туннелей"},
		// ShowSAMSessions/ShowSAMSession
		{"SAM disabled", "SAM выключен"},
		{"SAM session not found", "SAM сессия не найдена"},
		{"no sessions currently running", "нет запущенных сессий"},
		{"SAM Session", "SAM сессия"},
		// ShowI2PTunnels
		{"Server Tunnels", "Серверные туннели"},
		{"Client Forwards", "Клиентские переадресации"},
		{"Server Forwards", "Серверные переадресации"},
		// HandlePage
		{"Unknown page", "Неизвестная страница"},
		// HandleCommand, ShowError
		{"Invalid token", "Неверный токен"},
		{"SUCCESS", "УСПЕШНО"},
		{"ERROR", "ОШИБКА"},
		{"Unknown command", "Неизвестная команда"},
		{"Command accepted", "Команда принята"},
		{"Back to commands list", "Вернуться к списку команд"},
		{"You will be redirected in 5 seconds", "Вы будете переадресованы через 5 секунд"},
		// HTTP_COMMAND_KILLSTREAM
		{"Stream closed", "Стрим закрыт"},
		{"Stream not found or already was closed", "Стрим не найден или уже закрыт"},
		{"Destination not found", "Точка назначения не найдена"},
		{"StreamID can't be null", "StreamID не может быть пустым"},
		{"Return to destination page", "Вернуться на страницу точки назначения"},
		{"You will be redirected back in 5 seconds", "Вы будете переадресованы назад через 5 секунд"},
		// HTTP_COMMAND_LIMITTRANSIT
		{"Transit tunnels count must not exceed 65535", "Число транзитных туннелей не должно превышать 65535"},
		// HTTP_COMMAND_GET_REG_STRING
		{"Register at reg.i2p", "Зарегистрировать на reg.i2p"},
		{"Description", "Описание"},
		{"A bit information about service on domain", "Немного информации о сервисе на домене"},
		{"Submit", "Отправить"},
		{"Domain can't end with .b32.i2p", "Домен не может заканчиваться на .b32.i2p"},
		{"Domain must end with .i2p", "Домен должен заканчиваться на .i2p"},
		{"Such destination is not found", "Такая точка назначения не найдена"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		// ShowUptime
		{"days",    {"день", "дня", "дней"}},
		{"hours",   {"час", "часа", "часов"}},
		{"minutes", {"минуту", "минуты", "минут"}},
		{"seconds", {"секунду", "секунды", "секунд"}},
		{"", {"", ""}},
	};

	std::string GetString (std::string arg)
	{
		auto it = strings.find(arg);
		if (it == strings.end())
		{
			return arg;
		} else {
			return it->second;
		}
	}

	std::string GetPlural (std::string arg, int n)
	{
		auto it = plurals.find(arg);
		if (it == plurals.end())
		{
			return arg;
		} else {
			int form = plural(n);
			return it->second[form];
		}
	}

} // language
} // i18n
} // i2p
