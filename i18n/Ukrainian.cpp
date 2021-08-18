/*
* Copyright (c) 2021, The PurpleI2P Project
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

// Ukrainian localization file

namespace i2p
{
namespace i18n
{
namespace ukrainian // language namespace
{
	// language name in lowercase
	static std::string language = "ukrainian";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2;
	}

	static std::map<std::string, std::string> strings
	{
		{"KiB", "КіБ"},
		{"MiB", "МіБ"},
		{"GiB", "ГіБ"},
		{"building", "будується"},
		{"failed", "невдалий"},
		{"expiring", "завершується"},
		{"established", "працює"},
		{"unknown", "невідомо"},
		{"exploratory", "дослідницький"},
		{"<b>i2pd</b> webconsole", "Веб-консоль <b>i2pd</b>"},
		{"Main page", "Головна"},
		{"Router commands", "Команди маршрутизатора"},
		{"Local Destinations", "Локальні Призначення"},
		{"LeaseSets", "Лізсети"},
		{"Tunnels", "Тунелі"},
		{"Transit Tunnels", "Транзитні Тунелі"},
		{"Transports", "Транспорти"},
		{"I2P tunnels", "I2P тунелі"},
		{"SAM sessions", "SAM сесії"},
		{"ERROR", "ПОМИЛКА"},
		{"OK", "OK"},
		{"Testing", "Тестування"},
		{"Firewalled", "Заблоковано ззовні"},
		{"Unknown", "Невідомо"},
		{"Proxy", "Проксі"},
		{"Mesh", "MESH-мережа"},
		{"Error", "Помилка"},
		{"Clock skew", "Неточний час"},
		{"Offline", "Офлайн"},
		{"Symmetric NAT", "Симетричний NAT"},
		{"Uptime", "У мережі"},
		{"Network status", "Мережевий статус"},
		{"Network status v6", "Мережевий статус v6"},
		{"Stopping in", "Зупинка через"},
		{"Family", "Сімейство"},
		{"Tunnel creation success rate", "Успішно побудованих тунелів"},
		{"Received", "Отримано"},
		{"KiB/s", "КіБ/с"},
		{"Sent", "Відправлено"},
		{"Transit", "Транзит"},
		{"Data path", "Шлях до даних"},
		{"Hidden content. Press on text to see.", "Прихований вміст. Щоб відобразити, натисніть на текст."},
		{"Router Ident", "Ідентифікатор маршрутизатора"},
		{"Router Family", "Сімейство маршрутизатора"},
		{"Router Caps", "Прапорці маршрутизатора"},
		{"Version", "Версія"},
		{"Our external address", "Наша зовнішня адреса"},
		{"supported", "підтримується"},
		{"Routers", "Маршрутизатори"},
		{"Floodfills", "Флудфіли"},
		{"Client Tunnels", "Клієнтські Тунелі"},
		{"Services", "Сервіси"},
		{"Enabled", "Увімкнуто"},
		{"Disabled", "Вимкнуто"},
		{"Encrypted B33 address", "Шифровані B33 адреси"},
		{"Address registration line", "Рядок реєстрації адреси"},
		{"Domain", "Домен"},
		{"Generate", "Згенерувати"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Примітка:</b> отриманий рядок може бути використаний тільки для реєстрації доменів другого рівня (example.i2p). Для реєстрації піддоменів використовуйте i2pd-tools."},
		{"Address", "Адреса"},
		{"Type", "Тип"},
		{"EncType", "ТипШифр"},
		{"Inbound tunnels", "Вхідні тунелі"},
		{"ms", "мс"},
		{"Outbound tunnels", "Вихідні тунелі"},
		{"Tags", "Теги"},
		{"Incoming", "Вхідні"},
		{"Outgoing", "Вихідні"},
		{"Destination", "Призначення"},
		{"Amount", "Кількість"},
		{"Incoming Tags", "Вхідні Теги"},
		{"Tags sessions", "Сесії Тегів"},
		{"Status", "Статус"},
		{"Local Destination", "Локальні Призначення"},
		{"Streams", "Потоки"},
		{"Close stream", "Закрити потік"},
		{"I2CP session not found", "I2CP сесія не знайдена"},
		{"I2CP is not enabled", "I2CP не увікнуто"},
		{"Invalid", "Некоректний"},
		{"Store type", "Тип сховища"},
		{"Expires", "Завершується"},
		{"Non Expired Leases", "Не завершені Lease-и"},
		{"Gateway", "Шлюз"},
		{"TunnelID", "ID тунеля"},
		{"EndDate", "Закінчується"},
		{"not floodfill", "не флудфіл"},
		{"Queue size", "Розмір черги"},
		{"Run peer test", "Запустити тестування"},
		{"Decline transit tunnels", "Відхиляти транзитні тунелі"},
		{"Accept transit tunnels", "Ухвалювати транзитні тунелі"},
		{"Cancel graceful shutdown", "Скасувати плавну зупинку"},
		{"Start graceful shutdown", "Запустити плавну зупинку"},
		{"Force shutdown", "Примусова зупинка"},
		{"Reload external CSS styles", "Перезавантажити зовнішні стилі CSS"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Примітка:</b> будь-яка зроблена тут дія не є постійною та не змінює ваші конфігураційні файли."},
		{"Logging level", "Рівень логування"},
		{"Transit tunnels limit", "Обмеження транзитних тунелів"},
		{"Change", "Змінити"},
		{"Change language", "Змінити мову"},
		{"no transit tunnels currently built", "немає побудованих транзитних тунелів"},
		{"SAM disabled", "SAM вимкнуто"},
		{"no sessions currently running", "немає запущених сесій"},
		{"SAM session not found", "SAM сесія не знайдена"},
		{"SAM Session", "SAM сесія"},
		{"Server Tunnels", "Серверні Тунелі"},
		{"Client Forwards", "Клієнтські Переспрямування"},
		{"Server Forwards", "Серверні Переспрямування"},
		{"Unknown page", "Невідома сторінка"},
		{"Invalid token", "Невірний токен"},
		{"SUCCESS", "УСПІШНО"},
		{"Stream closed", "Потік зачинений"},
		{"Stream not found or already was closed", "Потік не знайдений або вже зачинений"},
		{"Destination not found", "Точка призначення не знайдена"},
		{"StreamID can't be null", "Ідентифікатор потоку не може бути порожнім"},
		{"Return to destination page", "Повернутися на сторінку точки призначення"},
		{"You will be redirected in 5 seconds", "Ви будете переадресовані через 5 секунд"},
		{"Transit tunnels count must not exceed 65535", "Кількість транзитних тунелів не повинна перевищувати 65535"},
		{"Back to commands list", "Повернутися до списку команд"},
		{"Register at reg.i2p", "Зареєструвати на reg.i2p"},
		{"Description", "Опис"},
		{"A bit information about service on domain", "Трохи інформації про сервіс на домені"},
		{"Submit", "Надіслати"},
		{"Domain can't end with .b32.i2p", "Домен не може закінчуватися на .b32.i2p"},
		{"Domain must end with .i2p", "Домен повинен закінчуватися на .i2p"},
		{"Such destination is not found", "Така точка призначення не знайдена"},
		{"Unknown command", "Невідома команда"},
		{"Command accepted", "Команда прийнята"},
		{"Proxy error", "Помилка проксі"},
		{"Proxy info", "Інформація проксі"},
		{"Proxy error: Host not found", "Помилка проксі: Адреса не знайдена"},
		{"Remote host not found in router's addressbook", "Віддалена адреса не знайдена в адресній книзі маршрутизатора"},
		{"You may try to find this host on jump services below", "Ви можете спробувати знайти дану адресу на джамп сервісах нижче"},
		{"Invalid request", "Некоректний запит"},
		{"Proxy unable to parse your request", "Проксі не може розібрати ваш запит"},
		{"addresshelper is not supported", "addresshelper не підтримується"},
		{"Host", "Адреса"},
		{"added to router's addressbook from helper", "доданий в адресну книгу маршрутизатора через хелпер"},
		{"Click here to proceed:", "Натисніть тут щоб продовжити:"},
		{"Continue", "Продовжити"},
		{"Addresshelper found", "Знайдено addresshelper"},
		{"already in router's addressbook", "вже в адресній книзі маршрутизатора"},
		{"Click here to update record:", "Натисніть тут щоб оновити запис:"},
		{"invalid request uri", "некоректний URI запиту"},
		{"Can't detect destination host from request", "Не вдалось визначити адресу призначення з запиту"},
		{"Outproxy failure", "Помилка зовнішнього проксі"},
		{"bad outproxy settings", "некоректні налаштування зовнішнього проксі"},
		{"not inside I2P network, but outproxy is not enabled", "не в I2P мережі, але зовнішній проксі не включений"},
		{"unknown outproxy url", "невідомий URL зовнішнього проксі"},
		{"cannot resolve upstream proxy", "не вдається визначити висхідний проксі"},
		{"hostname too long", "ім'я вузла надто довге"},
		{"cannot connect to upstream socks proxy", "не вдається підключитися до висхідного SOCKS проксі"},
		{"Cannot negotiate with socks proxy", "Не вдається домовитися з висхідним SOCKS проксі"},
		{"CONNECT error", "Помилка CONNECT запиту"},
		{"Failed to Connect", "Не вдалося підключитися"},
		{"socks proxy error", "помилка SOCKS проксі"},
		{"failed to send request to upstream", "не вдалося відправити запит висхідному проксі"},
		{"No Reply From socks proxy", "Немає відповіді від SOCKS проксі сервера"},
		{"cannot connect", "не вдалося підключитися"},
		{"http out proxy not implemented", "підтримка зовнішнього HTTP проксі сервера не реалізована"},
		{"cannot connect to upstream http proxy", "не вдалося підключитися до висхідного HTTP проксі сервера"},
		{"Host is down", "Вузол недоступний"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Не вдалося встановити з'єднання до запитаного вузла, можливо він не в мережі. Спробуйте повторити запит пізніше."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days", {"день", "дня", "днів"}},
		{"hours", {"годину", "години", "годин"}},
		{"minutes", {"хвилину", "хвилини", "хвилин"}},
		{"seconds", {"секунду", "секунди", "секунд"}},
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
