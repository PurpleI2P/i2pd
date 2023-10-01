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
		{"%.2f KiB", "%.2f КіБ"},
		{"%.2f MiB", "%.2f МіБ"},
		{"%.2f GiB", "%.2f ГіБ"},
		{"building", "будується"},
		{"failed", "невдалий"},
		{"expiring", "завершується"},
		{"established", "працює"},
		{"unknown", "невідомо"},
		{"exploratory", "дослідницький"},
		{"Purple I2P Webconsole", "Веб-консоль Purple I2P"},
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
		{"Clock skew", "Неточний час"},
		{"Offline", "Офлайн"},
		{"Symmetric NAT", "Симетричний NAT"},
		{"Full cone NAT", "Повний NAT"},
		{"No Descriptors", "Немає Описів"},
		{"Uptime", "У мережі"},
		{"Network status", "Мережевий статус"},
		{"Network status v6", "Мережевий статус v6"},
		{"Stopping in", "Зупинка через"},
		{"Family", "Сімейство"},
		{"Tunnel creation success rate", "Успішно побудованих тунелів"},
		{"Total tunnel creation success rate", "Загальна кількість створених тунелів"},
		{"Received", "Отримано"},
		{"%.2f KiB/s", "%.2f КіБ/с"},
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
		{"Expire LeaseSet", "Завершити LeaseSet"},
		{"Inbound tunnels", "Вхідні тунелі"},
		{"%dms", "%dмс"},
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
		{"Such destination is not found", "Така точка призначення не знайдена"},
		{"I2CP session not found", "I2CP сесія не знайдена"},
		{"I2CP is not enabled", "I2CP не увікнуто"},
		{"Invalid", "Некоректний"},
		{"Store type", "Тип сховища"},
		{"Expires", "Завершується"},
		{"Non Expired Leases", "Не завершені Lease-и"},
		{"Gateway", "Шлюз"},
		{"TunnelID", "ID тунеля"},
		{"EndDate", "Закінчується"},
		{"floodfill mode is disabled", "режим floodfill вимкнено"},
		{"Queue size", "Розмір черги"},
		{"Run peer test", "Запустити тестування"},
		{"Reload tunnels configuration", "Перезавантажити налаштування тунелів"},
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
		{"You will be redirected in %d seconds", "Ви будете переадресовані через %d секунд"},
		{"LeaseSet expiration time updated", "Час закінчення LeaseSet оновлено"},
		{"LeaseSet is not found or already expired", "LeaseSet не знайдено або вже закінчився"},
		{"Transit tunnels count must not exceed %d", "Кількість транзитних тунелів не повинна перевищувати %d"},
		{"Back to commands list", "Повернутися до списку команд"},
		{"Register at reg.i2p", "Зареєструвати на reg.i2p"},
		{"Description", "Опис"},
		{"A bit information about service on domain", "Трохи інформації про сервіс на домені"},
		{"Submit", "Надіслати"},
		{"Domain can't end with .b32.i2p", "Домен не може закінчуватися на .b32.i2p"},
		{"Domain must end with .i2p", "Домен повинен закінчуватися на .i2p"},
		{"Unknown command", "Невідома команда"},
		{"Command accepted", "Команда прийнята"},
		{"Proxy error", "Помилка проксі"},
		{"Proxy info", "Інформація проксі"},
		{"Proxy error: Host not found", "Помилка проксі: Адреса не знайдена"},
		{"Remote host not found in router's addressbook", "Віддалена адреса не знайдена в адресній книзі маршрутизатора"},
		{"You may try to find this host on jump services below", "Ви можете спробувати знайти дану адресу на джамп сервісах нижче"},
		{"Invalid request", "Некоректний запит"},
		{"Proxy unable to parse your request", "Проксі не може розібрати ваш запит"},
		{"Addresshelper is not supported", "Адресна книга не підтримується"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Хост %s <font color=red>вже в адресній книзі маршрутизатора</font>. <b>Будьте обережні: джерело цієї адреси може зашкодити!</b> Натисніть тут, щоб оновити запис: <a href=\"%s%s%s&update=true\">Продовжити</a>."},
		{"Addresshelper forced update rejected", "Адресна книга відхилила примусове оновлення"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Щоб додати хост <b>%s</b> в адресі маршрутизатора, натисніть тут: <a href=\"%s%s%s\">Продовжити</a>."},
		{"Addresshelper request", "Запит на адресну сторінку"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Хост %s доданий в адресну книгу маршрутизатора від помічника. Натисніть тут, щоб продовжити: <a href=\"%s\">Продовжити</a>."},
		{"Addresshelper adding", "Адреса додана"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "Хост %s <font color=red>вже в адресній книзі маршрутизатора</font>. Натисніть тут, щоб оновити запис: <a href=\"%s%s%s&update=true\">Продовжити</a>."},
		{"Addresshelper update", "Оновлення адресної книги"},
		{"Invalid request URI", "Некоректний URI запиту"},
		{"Can't detect destination host from request", "Не вдалось визначити адресу призначення з запиту"},
		{"Outproxy failure", "Помилка зовнішнього проксі"},
		{"Bad outproxy settings", "Некоректні налаштування зовнішнього проксі"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Адрес %s не в I2P мережі, але зовнішній проксі не включений"},
		{"Unknown outproxy URL", "Невідомий URL зовнішнього проксі"},
		{"Cannot resolve upstream proxy", "Не вдається визначити висхідний проксі"},
		{"Hostname is too long", "Ім'я вузла надто довге"},
		{"Cannot connect to upstream SOCKS proxy", "Не вдалося підключитися до висхідного SOCKS проксі сервера"},
		{"Cannot negotiate with SOCKS proxy", "Не вдається домовитися з висхідним SOCKS проксі"},
		{"CONNECT error", "Помилка CONNECT запиту"},
		{"Failed to connect", "Не вдалося підключитися"},
		{"SOCKS proxy error", "Помилка SOCKS проксі"},
		{"Failed to send request to upstream", "Не вдалося відправити запит висхідному проксі"},
		{"No reply from SOCKS proxy", "Немає відповіді від SOCKS проксі сервера"},
		{"Cannot connect", "Не вдалося підключитися"},
		{"HTTP out proxy not implemented", "Підтримка зовнішнього HTTP проксі сервера не реалізована"},
		{"Cannot connect to upstream HTTP proxy", "Не вдалося підключитися до висхідного HTTP проксі сервера"},
		{"Host is down", "Вузол недоступний"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Не вдалося встановити з'єднання до запитаного вузла, можливо він не в мережі. Спробуйте повторити запит пізніше."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d день", "%d дня", "%d днів"}},
		{"%d hours", {"%d годину", "%d години", "%d годин"}},
		{"%d minutes", {"%d хвилину", "%d хвилини", "%d хвилин"}},
		{"%d seconds", {"%d секунду", "%d секунди", "%d секунд"}},
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
