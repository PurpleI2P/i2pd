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

// Russian localization file

namespace i2p
{
namespace i18n
{
namespace russian // language namespace
{
	// language name in lowercase
	static std::string language = "russian";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n % 10 == 1 && n % 100 != 11 ? 0 : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2;
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f КиБ"},
		{"%.2f MiB", "%.2f МиБ"},
		{"%.2f GiB", "%.2f ГиБ"},
		{"building", "строится"},
		{"failed", "неудачный"},
		{"expiring", "истекает"},
		{"established", "работает"},
		{"unknown", "неизвестно"},
		{"exploratory", "исследовательский"},
		{"Purple I2P Webconsole", "Веб-консоль Purple I2P"},
		{"<b>i2pd</b> webconsole", "Веб-консоль <b>i2pd</b>"},
		{"Main page", "Главная"},
		{"Router commands", "Команды роутера"},
		{"Local Destinations", "Локальные назначения"},
		{"LeaseSets", "Лизсеты"},
		{"Tunnels", "Туннели"},
		{"Transit Tunnels", "Транзитные туннели"},
		{"Transports", "Транспорты"},
		{"I2P tunnels", "I2P туннели"},
		{"SAM sessions", "SAM сессии"},
		{"ERROR", "ОШИБКА"},
		{"OK", "OK"},
		{"Testing", "Тестирование"},
		{"Firewalled", "Заблокировано извне"},
		{"Unknown", "Неизвестно"},
		{"Proxy", "Прокси"},
		{"Mesh", "MESH-сеть"},
		{"Clock skew", "Не точное время"},
		{"Offline", "Оффлайн"},
		{"Symmetric NAT", "Симметричный NAT"},
		{"Full cone NAT", "Full cone NAT"},
		{"No Descriptors", "Нет дескрипторов"},
		{"Uptime", "В сети"},
		{"Network status", "Сетевой статус"},
		{"Network status v6", "Сетевой статус v6"},
		{"Stopping in", "Остановка через"},
		{"Family", "Семейство"},
		{"Tunnel creation success rate", "Успешно построенных туннелей"},
		{"Total tunnel creation success rate", "Общий процент успешно построенных туннелей"},
		{"Received", "Получено"},
		{"%.2f KiB/s", "%.2f КиБ/с"},
		{"Sent", "Отправлено"},
		{"Transit", "Транзит"},
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
		{"Client Tunnels", "Клиентские туннели"},
		{"Services", "Сервисы"},
		{"Enabled", "Включено"},
		{"Disabled", "Выключено"},
		{"Encrypted B33 address", "Шифрованные B33 адреса"},
		{"Address registration line", "Строка регистрации адреса"},
		{"Domain", "Домен"},
		{"Generate", "Сгенерировать"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Примечание:</b> полученная строка может быть использована только для регистрации доменов второго уровня (example.i2p). Для регистрации поддоменов используйте i2pd-tools."},
		{"Address", "Адрес"},
		{"Type", "Тип"},
		{"EncType", "ТипШифр"},
		{"Expire LeaseSet", "Просрочить Лизсет"},
		{"Inbound tunnels", "Входящие туннели"},
		{"%dms", "%dмс"},
		{"Outbound tunnels", "Исходящие туннели"},
		{"Tags", "Теги"},
		{"Incoming", "Входящие"},
		{"Outgoing", "Исходящие"},
		{"Destination", "Назначение"},
		{"Amount", "Количество"},
		{"Incoming Tags", "Входящие теги"},
		{"Tags sessions", "Сессии тегов"},
		{"Status", "Статус"},
		{"Local Destination", "Локальное назначение"},
		{"Streams", "Стримы"},
		{"Close stream", "Закрыть стрим"},
		{"Such destination is not found", "Такая точка назначения не найдена"},
		{"I2CP session not found", "I2CP сессия не найдена"},
		{"I2CP is not enabled", "I2CP не включен"},
		{"Invalid", "Некорректный"},
		{"Store type", "Тип хранилища"},
		{"Expires", "Истекает"},
		{"Non Expired Leases", "Не истекшие Lease-ы"},
		{"Gateway", "Шлюз"},
		{"TunnelID", "ID туннеля"},
		{"EndDate", "Заканчивается"},
		{"floodfill mode is disabled", "режим флудфила отключен"},
		{"Queue size", "Размер очереди"},
		{"Run peer test", "Запустить тестирование"},
		{"Reload tunnels configuration", "Перезагрузить конфигурацию туннелей"},
		{"Decline transit tunnels", "Отклонять транзитные туннели"},
		{"Accept transit tunnels", "Принимать транзитные туннели"},
		{"Cancel graceful shutdown", "Отменить плавную остановку"},
		{"Start graceful shutdown", "Запустить плавную остановку"},
		{"Force shutdown", "Принудительная остановка"},
		{"Reload external CSS styles", "Перезагрузить внешние CSS стили"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Примечание:</b> любое действие произведенное здесь не является постоянным и не изменяет ваши конфигурационные файлы."},
		{"Logging level", "Уровень логирования"},
		{"Transit tunnels limit", "Лимит транзитных туннелей"},
		{"Change", "Изменить"},
		{"Change language", "Изменение языка"},
		{"no transit tunnels currently built", "нет построенных транзитных туннелей"},
		{"SAM disabled", "SAM выключен"},
		{"no sessions currently running", "нет запущенных сессий"},
		{"SAM session not found", "SAM сессия не найдена"},
		{"SAM Session", "SAM сессия"},
		{"Server Tunnels", "Серверные туннели"},
		{"Client Forwards", "Клиентские перенаправления"},
		{"Server Forwards", "Серверные перенаправления"},
		{"Unknown page", "Неизвестная страница"},
		{"Invalid token", "Неверный токен"},
		{"SUCCESS", "УСПЕШНО"},
		{"Stream closed", "Стрим закрыт"},
		{"Stream not found or already was closed", "Стрим не найден или уже закрыт"},
		{"Destination not found", "Точка назначения не найдена"},
		{"StreamID can't be null", "StreamID не может быть пустым"},
		{"Return to destination page", "Вернуться на страницу точки назначения"},
		{"You will be redirected in %d seconds", "Вы будете переадресованы через %d секунд"},
		{"LeaseSet expiration time updated", "Время действия LeaseSet обновлено"},
		{"LeaseSet is not found or already expired", "Лизсет не найден или время действия уже истекло"},
		{"Transit tunnels count must not exceed %d", "Число транзитных туннелей не должно превышать %d"},
		{"Back to commands list", "Вернуться к списку команд"},
		{"Register at reg.i2p", "Зарегистрировать на reg.i2p"},
		{"Description", "Описание"},
		{"A bit information about service on domain", "Немного информации о сервисе на домене"},
		{"Submit", "Отправить"},
		{"Domain can't end with .b32.i2p", "Домен не может заканчиваться на .b32.i2p"},
		{"Domain must end with .i2p", "Домен должен заканчиваться на .i2p"},
		{"Unknown command", "Неизвестная команда"},
		{"Command accepted", "Команда принята"},
		{"Proxy error", "Ошибка прокси"},
		{"Proxy info", "Информация прокси"},
		{"Proxy error: Host not found", "Ошибка прокси: Узел не найден"},
		{"Remote host not found in router's addressbook", "Запрошенный узел не найден в адресной книге роутера"},
		{"You may try to find this host on jump services below", "Вы можете попробовать найти узел через джамп сервисы ниже"},
		{"Invalid request", "Некорректный запрос"},
		{"Proxy unable to parse your request", "Прокси не может разобрать ваш запрос"},
		{"Addresshelper is not supported", "Addresshelper не поддерживается"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Узел %s <font color=red>уже в адресной книге роутера</font>. <b>Будьте осторожны: источник данной ссылки может быть вредоносным!</b> Нажмите здесь, чтобы обновить запись: <a href=\"%s%s%s&update=true\">Продолжить</a>."},
		{"Addresshelper forced update rejected", "Принудительное обновление через Addresshelper отклонено"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Чтобы добавить узел <b>%s</b> в адресную книгу роутера, нажмите здесь: <a href=\"%s%s%s\">Продолжить</a>."},
		{"Addresshelper request", "Запрос добавления Addresshelper"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Узел %s добавлен в адресную книгу роутера через хелпер. Нажмите здесь, чтобы продолжить: <a href=\"%s\">Продолжить</a>."},
		{"Addresshelper adding", "Добавление Addresshelper"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Узел %s <font color=red>уже в адресной книге роутера</font>. Нажмите здесь, чтобы обновить запись: <a href=\"%s%s%s&update=true\">Продолжить</a>."},
		{"Addresshelper update", "Обновление записи через Addresshelper"},
		{"Invalid request URI", "Некорректный URI запроса"},
		{"Can't detect destination host from request", "Не удалось определить адрес назначения из запроса"},
		{"Outproxy failure", "Ошибка внешнего прокси"},
		{"Bad outproxy settings", "Некорректные настройки внешнего прокси"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Узел %s не в I2P сети, но внешний прокси не включен"},
		{"Unknown outproxy URL", "Неизвестный URL внешнего прокси"},
		{"Cannot resolve upstream proxy", "Не удается определить вышестоящий прокси"},
		{"Hostname is too long", "Имя хоста слишком длинное"},
		{"Cannot connect to upstream SOCKS proxy", "Не удалось подключиться к вышестоящему SOCKS прокси серверу"},
		{"Cannot negotiate with SOCKS proxy", "Не удается договориться с вышестоящим SOCKS прокси"},
		{"CONNECT error", "Ошибка CONNECT запроса"},
		{"Failed to connect", "Не удалось соединиться"},
		{"SOCKS proxy error", "Ошибка SOCKS прокси"},
		{"Failed to send request to upstream", "Не удалось отправить запрос вышестоящему прокси серверу"},
		{"No reply from SOCKS proxy", "Нет ответа от SOCKS прокси сервера"},
		{"Cannot connect", "Не удалось подключиться"},
		{"HTTP out proxy not implemented", "Поддержка внешнего HTTP прокси сервера не реализована"},
		{"Cannot connect to upstream HTTP proxy", "Не удалось подключиться к вышестоящему HTTP прокси серверу"},
		{"Host is down", "Узел недоступен"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Не удалось установить соединение к запрошенному узлу, возможно он не в сети. Попробуйте повторить запрос позже."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days",    {"%d день", "%d дня", "%d дней"}},
		{"%d hours",   {"%d час", "%d часа", "%d часов"}},
		{"%d minutes", {"%d минуту", "%d минуты", "%d минут"}},
		{"%d seconds", {"%d секунду", "%d секунды", "%d секунд"}},
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
