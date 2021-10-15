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
namespace uzbek // language namespace
{
	// language name in lowercase
	static std::string language = "uzbek";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n > 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"KiB", "KiB"},
		{"MiB", "MiB"},
		{"GiB", "GiB"},
		{"building", "qurilish"},
		{"failed", "muvaffaqiyatsiz"},
		{"expiring", "muddati tugaydi"},
		{"established", "aloqa o'rnatildi"},
		{"unknown", "noma'lum"},
		{"exploratory", "tadqiqiy"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> veb -konsoli"},
		{"Main page", "Asosiy sahifa"},
		{"Router commands", "Router buyruqlari"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Tunnellar"},
		{"Transit Tunnels", "Tranzit Tunellar"},
		{"Transports", "Transportlar"},
		{"I2P tunnels", "I2P tunnellar"},
		{"SAM sessions", "SAM sessiyalari"},
		{"ERROR", "XATO"},
		{"OK", "OK"},
		{"Testing", "Testlash"},
		{"Firewalled", "Xavfsizlik devori bilan himoyalangan"},
		{"Unknown", "Notanish"},
		{"Proxy", "Proksi"},
		{"Mesh", "Mesh To'r"},
		{"Error", "Xato"},
		{"Clock skew", "Aniq vaqt emas"},
		{"Offline", "Oflayn"},
		{"Symmetric NAT", "Simmetrik NAT"},
		{"Uptime", "Ish vaqti"},
		{"Network status", "Tarmoq holati"},
		{"Network status v6", "Tarmoq holati v6"},
		{"Stopping in", "Ichida to'xtatish"},
		{"Family", "Oila"},
		{"Tunnel creation success rate", "Tunnel yaratish muvaffaqiyat darajasi"},
		{"Received", "Qabul qilindi"},
		{"KiB/s", "KiB/s"},
		{"Sent", "Yuborilgan"},
		{"Transit", "Tranzit"},
		{"Data path", "Ma'lumotlar yo'li"},
		{"Hidden content. Press on text to see.", "Yashirin tarkib. Ko'rish uchun matn ustida bosing."},
		{"Router Ident", "Router identifikatori"},
		{"Router Family", "Router Oila"},
		{"Router Caps", "Router bayroqlari"},
		{"Version", "Versiya"},
		{"Our external address", "Bizning tashqi manzilimiz"},
		{"supported", "qo'llab -quvvatlanadi"},
		{"Routers", "Routerlar"},
		{"Floodfills", "Floodfills"},
		{"Client Tunnels", "Mijoz tunellari"},
		{"Services", "Xizmatlar"},
		{"Enabled", "Yoqilgan"},
		{"Disabled", "O'chirilgan"},
		{"Encrypted B33 address", "Shifrlangan B33 manzil"},
		{"Address registration line", "Manzilni ro'yxatga olish liniyasi"},
		{"Domain", "Domen"},
		{"Generate", "Varatish"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Eslatma:</b> natija satridan faqat 2LD domenlarini ro'yxatdan o'tkazish uchun foydalanish mumkin (example.i2p). Subdomenlarni ro'yxatdan o'tkazish uchun i2pd-tools dan foydalaning."},
		{"Address", "Manzil"},
		{"Type", "Turi"},
		{"EncType", "ShifrlashTuri"},
		{"Inbound tunnels", "Kirish tunnellari"},
		{"ms", "ms"},
		{"Outbound tunnels", "Chiquvchi tunnellar"},
		{"Tags", "Teglar"},
		{"Incoming", "Kiruvchi"},
		{"Outgoing", "Chiquvchi"},
		{"Destination", "Manzilgoh"},
		{"Amount", "Yig'indi"},
		{"Incoming Tags", "Kiruvchi teglar"},
		{"Tags sessions", "Teglar sessiyalari"},
		{"Status", "Holat"},
		{"Streams", "Strim"},
		{"Close stream", "Strimni o'chirish"},
		{"I2CP session not found", "I2CP sessiyasi topilmadi"},
		{"I2CP is not enabled", "I2CP yoqilmagan"},
		{"Invalid", "Noto'g'ri"},
		{"Store type", "Saqlash turi"},
		{"Expires", "Muddati tugaydi"},
		{"Non Expired Leases", "Muddati O'tmagan Leases"},
		{"Gateway", "Kirish yo'li"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Tugash Sanasi"},
		{"not floodfill", "floodfill emas"},
		{"Queue size", "Navbat hajmi"},
		{"Run peer test", "Sinovni boshlang"},
		{"Decline transit tunnels", "Tranzit tunnellarni rad etish"},
		{"Accept transit tunnels", "Tranzit tunnellarni qabul qilish"},
		{"Cancel graceful shutdown", "Yumshoq to'xtashni bekor qiling"},
		{"Start graceful shutdown", "Yumshoq to'xtashni boshlang"},
		{"Force shutdown", "Bizning tashqi manzilimiz"},
		{"Reload external CSS styles", "Tashqi CSS uslublarini qayta yuklang"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Eslatma:</b> bu erda qilingan har qanday harakat doimiy emas va konfiguratsiya fayllarini o'zgartirmaydi."},
		{"Transit tunnels limit", "Tranzit tunellar chegarasi"},
		{"Change", "O'zgartirish"},
		{"Change language", "Tilni o'zgartirish"},
		{"no transit tunnels currently built", "qurilgan tranzit tunnellari yo'q"},
		{"SAM disabled", "SAM o'chirilgan"},
		{"no sessions currently running", "hech qanday ishlaydigan sessiyalar yo'q"},
		{"SAM session not found", "SAM sessiyasi topilmadi"},
		{"SAM Session", "SAM sessiyasi"},
		{"Server Tunnels", "Server Tunellari"},
		{"Client Forwards", "Mijozlarni Yo'naltirish"},
		{"Server Forwards", "Serverni Yo'naltirish"},
		{"Unknown page", "Noma'lum sahifa"},
		{"Invalid token", "Noto‘g‘ri belgi"},
		{"SUCCESS", "Muvaffaqiyat"},
		{"Stream closed", "Strim yopiq"},
		{"Stream not found or already was closed", "Strim topilmadi yoki allaqachon yopilgan"},
		{"Destination not found", "Yo'nalish topilmadi"},
		{"StreamID can't be null", "StreamID bo'sh bo'lishi mumkin emas"},
		{"Return to destination page", "Belgilangan sahifaga qaytish"},
		{"You will be redirected in 5 seconds", "Siz 5 soniyada qayta yo'naltirilasiz"},
		{"Transit tunnels count must not exceed 65535", "Tranzit tunnellar soni 65535 dan oshmasligi kerak"},
		{"Back to commands list", "Buyruqlar ro'yxatiga qaytish"},
		{"Register at reg.i2p", "Reg.i2p-da ro'yxatdan o'ting"},
		{"Description", "Tavsif"},
		{"A bit information about service on domain", "Domen xizmatlari haqida bir oz ma'lumot"},
		{"Submit", "Yuborish"},
		{"Domain can't end with .b32.i2p", "Domen .b32.i2p bilan tugashi mumkin emas"},
		{"Domain must end with .i2p", "Domen .i2p bilan tugashi kerak"},
		{"Such destination is not found", "Bunday yo'nalish topilmadi"},
		{"Unknown command", "Noma'lum buyruq"},
		{"Command accepted", "Buyruq qabul qilindi"},
		{"Proxy error", "Proksi xatosi"},
		{"Proxy info", "Proksi ma'lumotlari"},
		{"Proxy error: Host not found", "Proksi xatosi: Xost topilmadi"},
		{"Remote host not found in router's addressbook", "Masofaviy xost yo'riqnoma manzillar kitobida topilmadi"},
		{"Invalid request", "Noto‘g‘ri so‘rov"},
		{"Proxy unable to parse your request", "Proksi sizning so'rovingizni tahlil qila olmaydi"},
		{"addresshelper is not supported", "addresshelper qo'llab -quvvatlanmaydi"},
		{"Host", "Xost"},
		{"Addresshelper found", "Addresshelper topildi"},
		{"invalid request uri", "noto'g'ri URI so'rovi"},
		{"Can't detect destination host from request", "So‘rov orqali manzil xostini aniqlab bo'lmayapti"},
		{"Outproxy failure", "Tashqi proksi muvaffaqiyatsizligi"},
		{"bad outproxy settings", "noto'g'ri tashqi proksi -server sozlamalari"},
		{"not inside I2P network, but outproxy is not enabled", "I2P tarmog'ida emas, lekin tashqi proksi yoqilmagan"},
		{"unknown outproxy url", "noma'lum outproxy url"},
		{"cannot resolve upstream proxy", "yuqoridagi proksi -serverni aniqlab olib bolmaydi"},
		{"hostname too long", "xost nomi juda uzun"},
		{"cannot connect to upstream socks proxy", "yuqori soks proksi -serveriga ulanib bo'lmaydi"},
		{"Cannot negotiate with socks proxy", "Soks proksi bilan muzokara olib bo'lmaydi"},
		{"CONNECT error", "CONNECT xatosi"},
		{"Failed to Connect", "Ulanmadi"},
		{"socks proxy error", "soks proksi xatosi"},
		{"failed to send request to upstream", "yuqori http proksi-serveriga ulanib bo'lmadi"},
		{"No Reply From socks proxy", "Soks-proksidan javob yo'q"},
		{"cannot connect", "ulab bo'lmaydi"},
		{"http out proxy not implemented", "tashqi HTTP proksi -serverni qo'llab -quvvatlash amalga oshirilmagan"},
		{"cannot connect to upstream http proxy", "yuqori http proksi-serveriga ulanib bo'lmadi"},
		{"Host is down", "Xost ishlamayapti"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Talab qilingan xost bilan aloqa o'rnatilmadi, u ishlamay qolishi mumkin. Iltimos keyinroq qayta urinib ko'ring."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days", {"kun", "kunlar"}},
		{"hours", {"soat", "soat"}},
		{"minutes", {"daqiqa", "daqiqalar"}},
		{"seconds", {"soniya", "soniyalar"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
