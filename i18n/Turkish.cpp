/*
* Copyright (c) 2023, The PurpleI2P Project
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

// Turkish localization file

namespace i2p
{
namespace i18n
{
namespace turkish // language namespace
{
	// language name in lowercase
	static std::string language = "turkish";

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
		{"building", "kuruluyor"},
		{"failed", "başarısız"},
		{"expiring", "süresi geçiyor"},
		{"established", "kurulmuş"},
		{"unknown", "bilinmeyen"},
		{"Purple I2P Webconsole", "Mor I2P Webkonsolu"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> webkonsolu"},
		{"Main page", "Ana sayfa"},
		{"Router commands", "Router komutları"},
		{"Local Destinations", "Yerel Hedefler"},
		{"Tunnels", "Tüneller"},
		{"Transit Tunnels", "Transit Tünelleri"},
		{"Transports", "Taşıma"},
		{"I2P tunnels", "I2P tünelleri"},
		{"SAM sessions", "SAM oturumları"},
		{"ERROR", "HATA"},
		{"OK", "TAMAM"},
		{"Testing", "Test ediliyor"},
		{"Firewalled", "Güvenlik Duvarı Kısıtlaması"},
		{"Unknown", "Bilinmeyen"},
		{"Proxy", "Proxy"},
		{"Clock skew", "Saat sorunu"},
		{"Offline", "Çevrimdışı"},
		{"Symmetric NAT", "Simetrik NAT"},
		{"Full cone NAT", "Full cone NAT"},
		{"No Descriptors", "Tanımlayıcı Yok"},
		{"Uptime", "Bağlantı süresi"},
		{"Network status", "Ağ durumu"},
		{"Network status v6", "Ağ durumu v6"},
		{"Family", "Aile"},
		{"Tunnel creation success rate", "Tünel oluşturma başarı oranı"},
		{"Received", "Alındı"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Gönderildi"},
		{"Transit", "Transit"},
		{"Data path", "Veri yolu"},
		{"Hidden content. Press on text to see.", "Gizlenmiş içerik. Görmek için yazıya tıklayınız."},
		{"Router Family", "Router Familyası"},
		{"Decline transit tunnels", "Transit tünellerini reddet"},
		{"Accept transit tunnels", "Transit tünellerini kabul et"},
		{"Cancel graceful shutdown", "Düzgün durdurmayı iptal Et"},
		{"Start graceful shutdown", "Düzgün durdurmayı başlat"},
		{"Force shutdown", "Durdurmaya zorla"},
		{"Reload external CSS styles", "Harici CSS stilini yeniden yükle"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>Not:</b> burada yapılan ayarların hiçbiri kalıcı değildir ve ayar dosyalarınızı değiştirmez."},
		{"Logging level", "Kayıt tutma seviyesi"},
		{"Transit tunnels limit", "Transit tünel limiti"},
		{"Change", "Değiştir"},
		{"Change language", "Dil değiştir"},
		{"no transit tunnels currently built", "kurulmuş bir transit tüneli bulunmamakta"},
		{"SAM disabled", "SAM devre dışı"},
		{"no sessions currently running", "hiçbir oturum şu anda çalışmıyor"},
		{"SAM session not found", "SAM oturumu bulunamadı"},
		{"SAM Session", "SAM oturumu"},
		{"Server Tunnels", "Sunucu Tünelleri"},
		{"Unknown page", "Bilinmeyen sayfa"},
		{"Invalid token", "Geçersiz token"},
		{"SUCCESS", "BAŞARILI"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d gün", "%d gün"}},
		{"%d hours", {"%d saat", "%d saat"}},
		{"%d minutes", {"%d dakika", "%d dakika"}},
		{"%d seconds", {"%d saniye", "%d saniye"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
