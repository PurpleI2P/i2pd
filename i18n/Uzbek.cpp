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
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "yaratilmoqda"},
		{"failed", "muvaffaqiyatsiz"},
		{"expiring", "muddati tugaydi"},
		{"established", "aloqa o'rnatildi"},
		{"unknown", "noma'lum"},
		{"exploratory", "tadqiqiy"},
		{"Purple I2P Webconsole", "Veb-konsoli Purple I2P"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> veb-konsoli"},
		{"Main page", "Asosiy sahifa"},
		{"Router commands", "Router buyruqlari"},
		{"Local Destinations", "Mahalliy joylanishlar"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Tunnellar"},
		{"Transit Tunnels", "Tranzit Tunellari"},
		{"Transports", "Transportlar"},
		{"I2P tunnels", "I2P tunnellari"},
		{"SAM sessions", "SAM sessiyalari"},
		{"ERROR", "XATO"},
		{"OK", "OK"},
		{"Testing", "Testlash"},
		{"Firewalled", "Xavfsizlik devori bilan himoyalangan"},
		{"Unknown", "Notanish"},
		{"Proxy", "Proksi"},
		{"Mesh", "Mesh To'r"},
		{"Clock skew", "Aniq vaqt emas"},
		{"Offline", "Oflayn"},
		{"Symmetric NAT", "Simmetrik NAT"},
		{"Full cone NAT", "Full cone NAT"},
		{"No Descriptors", "Deskriptorlar yo'q"},
		{"Uptime", "Ish vaqti"},
		{"Network status", "Tarmoq holati"},
		{"Network status v6", "Tarmoq holati v6"},
		{"Stopping in", "Ichida to'xtatish"},
		{"Family", "Oila"},
		{"Tunnel creation success rate", "Tunnel yaratish muvaffaqiyat darajasi"},
		{"Total tunnel creation success rate", "Tunnel yaratishning umumiy muvaffaqiyat darajasi"},
		{"Received", "Qabul qilindi"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Yuborilgan"},
		{"Transit", "Tranzit"},
		{"Data path", "Ma'lumotlar joylanishi"},
		{"Hidden content. Press on text to see.", "Yashirin tarkib. Ko'rish uchun matn ustida bosing."},
		{"Router Ident", "Router identifikatori"},
		{"Router Family", "Router oilasi"},
		{"Router Caps", "Router Bayroqlari"},
		{"Version", "Versiya"},
		{"Our external address", "Bizning tashqi manzilimiz"},
		{"supported", "qo'llab-quvvatlanadi"},
		{"Routers", "Routerlar"},
		{"Floodfills", "Floodfills"},
		{"Client Tunnels", "Mijoz Tunellari"},
		{"Services", "Xizmatlar"},
		{"Enabled", "Yoqilgan"},
		{"Disabled", "O'chirilgan"},
		{"Encrypted B33 address", "Shifrlangan B33 manzil"},
		{"Address registration line", "Manzilni ro'yxatga olish liniyasi"},
		{"Domain", "Domen"},
		{"Generate", "Yaratish"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>Eslatma:</b> natija satridan faqat 2LD domenlarini ro'yxatdan o'tkazish uchun foydalanish mumkin (example.i2p). Subdomenlarni ro'yxatdan o'tkazish uchun 'i2pd-tools'dan foydalaning."},
		{"Address", "Manzil"},
		{"Type", "Turi"},
		{"EncType", "ShifrlashTuri"},
		{"Expire LeaseSet", "LeaseSet muddati tugaydi"},
		{"Inbound tunnels", "Kirish tunnellari"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Chiquvchi tunnellar"},
		{"Tags", "Teglar"},
		{"Incoming", "Kiruvchi"},
		{"Outgoing", "Chiquvchi"},
		{"Destination", "Manzilgoh"},
		{"Amount", "Soni"},
		{"Incoming Tags", "Kiruvchi teglar"},
		{"Tags sessions", "Teglar sessiyalari"},
		{"Status", "Holat"},
		{"Local Destination", "Mahalliy joylanish"},
		{"Streams", "Strim"},
		{"Close stream", "Strimni o'chirish"},
		{"Such destination is not found", "Bunday yo'nalish topilmadi"},
		{"I2CP session not found", "I2CP sessiyasi topilmadi"},
		{"I2CP is not enabled", "I2CP yoqilmagan"},
		{"Invalid", "Noto'g'ri"},
		{"Store type", "Saqlash turi"},
		{"Expires", "Muddati tugaydi"},
		{"Non Expired Leases", "Muddati O'tmagan Leases"},
		{"Gateway", "Kirish yo'li"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Tugash Sanasi"},
		{"floodfill mode is disabled", "floodfill rejimi o'chirilgan"},
		{"Queue size", "Navbat hajmi"},
		{"Run peer test", "Sinovni boshlang"},
		{"Reload tunnels configuration", "Tunnel konfiguratsiyasini qayta yuklash"},
		{"Decline transit tunnels", "Tranzit tunnellarini rad etish"},
		{"Accept transit tunnels", "Tranzit tunnellarni qabul qilish"},
		{"Cancel graceful shutdown", "Yumshoq to'xtashni bekor qilish"},
		{"Start graceful shutdown", "Yumshoq to'xtashni boshlash"},
		{"Force shutdown", "Majburiy to'xtatish"},
		{"Reload external CSS styles", "Tashqi CSS uslublarini qayta yuklang"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Eslatma:</b> shu yerda qilingan har qanday harakat doimiy emas va konfiguratsiya fayllarini o'zgartirmaydi."},
		{"Logging level", "Jurnal darajasi"},
		{"Transit tunnels limit", "Tranzit tunellarning chegarasi"},
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
		{"Return to destination page", "Manzilgoh sahifasiga qaytish"},
		{"You will be redirected in %d seconds", "Siz %d soniyadan so‘ng boshqa yo‘nalishga yo‘naltirilasiz"},
		{"LeaseSet expiration time updated", "LeaseSet amal qilish muddati yangilandi"},
		{"LeaseSet is not found or already expired", "LeaseSet topilmadi yoki muddati tugagan"},
		{"Transit tunnels count must not exceed %d", "Tranzit tunnellar soni %d dan oshmasligi kerak"},
		{"Back to commands list", "Buyruqlar ro'yxatiga qaytish"},
		{"Register at reg.i2p", "Reg.i2p-da ro'yxatdan o'ting"},
		{"Description", "Tavsif"},
		{"A bit information about service on domain", "Domen xizmatlari haqida bir oz ma'lumot"},
		{"Submit", "Yuborish"},
		{"Domain can't end with .b32.i2p", "Domen .b32.i2p bilan tugashi mumkin emas"},
		{"Domain must end with .i2p", "Domen .i2p bilan tugashi kerak"},
		{"Unknown command", "Noma'lum buyruq"},
		{"Command accepted", "Buyruq qabul qilindi"},
		{"Proxy error", "Proksi xatosi"},
		{"Proxy info", "Proksi ma'lumotlari"},
		{"Proxy error: Host not found", "Proksi xatosi: Xost topilmadi"},
		{"Remote host not found in router's addressbook", "Masofaviy xost yo'riqnoma manzillar kitobida topilmadi"},
		{"You may try to find this host on jump services below", "Siz xost quyida o'tish xizmatlari orqali topishga harakat qilishingiz mumkin"},
		{"Invalid request", "Noto‘g‘ri so‘rov"},
		{"Proxy unable to parse your request", "Proksi sizning so'rovingizni aniqlab ololmayapti"},
		{"Addresshelper is not supported", "Addresshelper qo'llab-quvvatlanmaydi"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "%s xosti <font color=red>allaqachon routerning manzillar kitobida</font>. <b>Ehtiyot bo'ling: bu URL manbasi zararli bo'lishi mumkin!</b> Yozuvni yangilash uchun bu yerni bosing: <a href=\"%s%s%s&update=true\">Davom etish</a>."},
		{"Addresshelper forced update rejected", "Addresshelperni majburiy yangilash rad etildi"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Routerning manzillar kitobiga <b>%s</b> xostini qo'shish uchun bu yerni bosing: <a href=\"%s%s%s\">Davom etish</a>."},
		{"Addresshelper request", "Addresshelper so'rovi"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "Yordamchidan router manzillar kitobiga %s xost qo‘shildi. Davom etish uchun bu yerga bosing: <a href=\"%s\">Davom etish</a>."},
		{"Addresshelper adding", "Addresshelperni qo'shish"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "%s xosti <font color=red>allaqachon routerning manzillar kitobida</font>. Yozuvni yangilash uchun shu yerni bosing: <a href=\"%s%s%s&update=true\">Davom etish</a>."},
		{"Addresshelper update", "Addresshelperni yangilash"},
		{"Invalid request URI", "Noto'g'ri URI so'rovi"},
		{"Can't detect destination host from request", "So‘rov orqali manzil xostini aniqlab bo'lmayapti"},
		{"Outproxy failure", "Tashqi proksi muvaffaqiyatsizligi"},
		{"Bad outproxy settings", "Noto'g'ri tashqi proksi-server sozlamalari"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "Xost %s I2P tarmog'ida emas, lekin tashqi proksi yoqilmagan"},
		{"Unknown outproxy URL", "Noma'lum outproxy URL"},
		{"Cannot resolve upstream proxy", "Yuqoridagi 'proxy-server'ni aniqlab olib bolmayapti"},
		{"Hostname is too long", "Xost nomi juda uzun"},
		{"Cannot connect to upstream SOCKS proxy", "Yuqori 'SOCKS proxy'ga ulanib bo'lmayapti"},
		{"Cannot negotiate with SOCKS proxy", "'SOCKS proxy' bilan muzokara olib bo'lmaydi"},
		{"CONNECT error", "CONNECT xatosi"},
		{"Failed to connect", "Ulanib bo'lmayapti"},
		{"SOCKS proxy error", "'SOCKS proxy' xatosi"},
		{"Failed to send request to upstream", "Yuqori proksi-serveriga so'rovni uborib bo'lmadi"},
		{"No reply from SOCKS proxy", "'SOCKS proxy'dan javob yo'q"},
		{"Cannot connect", "Ulanib bo'lmaydi"},
		{"HTTP out proxy not implemented", "Tashqi HTTP proksi-serverni qo'llab-quvvatlash amalga oshirilmagan"},
		{"Cannot connect to upstream HTTP proxy", "Yuqori 'HTTP proxy'ga ulanib bo'lmayapti"},
		{"Host is down", "Xost ishlamayapti"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Talab qilingan xost bilan aloqa o'rnatilmadi, u ishlamay qolishi mumkin. Iltimos keyinroq qayta urinib ko'ring."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d kun", "%d kun"}},
		{"%d hours", {"%d soat", "%d soat"}},
		{"%d minutes", {"%d daqiqa", "%d daqiqa"}},
		{"%d seconds", {"%d soniya", "%d soniya"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
