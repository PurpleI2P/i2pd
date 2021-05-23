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
		{"Can't create connection to requested host, it may be down. Please try again later.", "Не удалось установить соединение к запрошенному адресу, возможно он не в сети. Попробуйте повторить запрос позже."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days",    {"день", "дня", "дней"}},
		{"hours",   {"час", "часа", "часов"}},
		{"minutes", {"минута", "минуты", "минут"}},
		{"seconds", {"секунда", "секунды", "секунд"}},
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
