/*
* Copyright (c) 2026, The PurpleI2P Project
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

// Persian localization file

namespace i2p
{
namespace i18n
{
namespace persian // language namespace
{
	// language name in lowercase
	static std::string language = "persian";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n > 1 ? 1 : 0;
	}

	// Right to Left language?
	static bool rtl = false;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f کیلوبیت"},
		{"%.2f MiB", "%.2f مگابیت"},
		{"%.2f GiB", "%.2f گیگابیت"},
		{"building", "در حال ساخت"},
		{"failed", "ناموفق"},
		{"expiring", "در حال منقضی شدن"},
		{"established", "برقرار شد"},
		{"unknown", "ناشناخته"},
		{"exploratory", "اکتشافی"},
		{"Purple I2P Webconsole", "کنسول وب i2pd"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> کنسول وب"},
		{"Main page", "صفحه اصلی"},
		{"Router commands", "دستور‌‌‌های روتر"},
		{"Local Destinations", "مقاصد محلی"},
		{"LeaseSets", "دسته های اجاره‌ای"},
		{"Tunnels", "تونل‌ها"},
		{"Transit Tunnels", "تونل‌های عبوری"},
		{"Transports", "انتقال ها"},
		{"I2P tunnels", "تونل های I2P"},
		{"SAM sessions", "نشست های SAM"},
		{"ERROR", "خطا"},
		{"OK", "تایید"},
		{"Testing", "در حال آزمایش"},
		{"Firewalled", "دیوار آتش فعال"},
		{"Unknown", "ناشناخته"},
		{"Proxy", "پراکسی"},
		{"Mesh", "شبکه"},
		{"Clock skew", "انحراف ساعت"},
		{"Offline", "خاموش"},
		{"Symmetric NAT", "NAT متقارن"},
		{"Full cone NAT", "NAT مخروطی کامل"},
		{"No Descriptors", "توصیف گری نیست"},
		{"Uptime", "زمان كاركرد"},
		{"Network status", "وضعیت شبکه"},
		{"Network status v6", "وضعیت شبکه نسخه 6"},
		{"Stopping in", "مکث کوتاه در"},
		{"Family", "خانواده"},
		{"Tunnel creation success rate", "میزان موفقیت در ایجاد تونل"},
		{"Total tunnel creation success rate", "میزان کلی موفقیت در ایجاد تونل"},
		{"Received", "دریافت شده"},
		{"%.2f KiB/s", "%.2f کیلوبیت/ثانیه"},
		{"Sent", "ارسال شده"},
		{"Transit", "حمل و نقل"},
		{"Data path", "مسیر اطلاعات"},
		{"Hidden content. Press on text to see.", "محتوای پنهان. برای دیدن، روی متن کلیک کنید."},
		{"Router Ident", "شناسه روتر"},
		{"Router Family", "شناسه روتر"},
		{"Router Caps", "ویژگی‌های روتر"},
		{"Version", "نسخه"},
		{"Our external address", "نشانی خارجی ما"},
		{"supported", "پشتیبانی شده"},
		{"Routers", "روترها"},
		{"Floodfills", "Floodfills"},
		{"Client Tunnels", "تونل‌های کلاینت"},
		{"Services", "سرویس‌ها"},
		{"Enabled", "فعال"},
		{"Disabled", "غیرفعال"},
		{"Encrypted B33 address", "نشانی رمزگذاری شده B33"},
		{"Address registration line", "خط ثبت نشانی"},
		{"Domain", "دامنه"},
		{"Generate", "تولید کردن"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>نکته:</b>رشته نتیجه فقط برای ثبت دامنه‌های سطح دوم 2LD قابل استفاده است (نمونه: example.i2p). برای ثبت زیردامنه‌ها لطفاً از i2pd-tools استفاده کنید."},
		{"Address", "نشانی"},
		{"Type", "نوع"},
		{"EncType", "نوع رمزنگاری"},
		{"Expire LeaseSet", "منقضی شدن LeaseSet"},
		{"Inbound tunnels", "تونل‌های ورودی"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "تونل‌های خروجی"},
		{"Tags", "برچسب‌ها"},
		{"Incoming", "ورودی"},
		{"Outgoing", "خروجی"},
		{"Destination", "مقصد"},
		{"Amount", "مقدار"},
		{"Incoming Tags", "برچسب‌های ورودی"},
		{"Tags sessions", "برچسب‌های نشست‌ها"},
		{"Status", "وضعیت"},
		{"Local Destination", "مقصد محلی"},
		{"Streams", "جریان‌ها"},
		{"Close stream", "بستن جریان"},
		{"Such destination is not found", "چنین مقصدی یافت نشد"},
		{"I2CP session not found", "نشست I2CP یافت نشد"},
		{"I2CP is not enabled", "I2CP فعال نیست"},
		{"Invalid", "نا‌معتبر"},
		{"Store type", "نوع ذخیره‌سازی"},
		{"Expires", "انقضا"},
		{"Non Expired Leases", "اجاره‌های منقضی نشده"},
		{"Gateway", "درگاه"},
		{"TunnelID", "شناسه تونل"},
		{"EndDate", "تاریخ پایان"},
		{"floodfill mode is disabled", "حالت Floodfill غیرفعال است"},
		{"Queue size", "اندازه صف"},
		{"Run peer test", "اجرای آزمون همتا"},
		{"Reload tunnels configuration", "بارگذاری دوباره پیکربندی تونل‌ها"},
		{"Decline transit tunnels", "نپذیرفتن تونل‌های عبوری"},
		{"Accept transit tunnels", "پذیرفتن تونل‌های عبوری"},
		{"Cancel graceful shutdown", "لغو خاموش‌سازی امن"},
		{"Start graceful shutdown", "شروع خاموش‌سازی امن"},
		{"Force shutdown", "خاموش کردن اجباری"},
		{"Reload external CSS styles", "بارگذاری دوباره سبک‌های CSS خارجی"},
		{"<b>Note:</b> any action performed here is not persistent and does not change your config files.", "<b>نکته:</b> هر تغییری که در اینجا انجام شود ماندگار نیست و تغییری در فایل‌های پیکربندی شما ایجاد نمی‌کند."},
		{"Logging level", "سطح ثبت گزارش"},
		{"Transit tunnels limit", "محدودیت تونل‌های عبوری"},
		{"Change", "تغییر"},
		{"Change language", "تغییر زبان"},
		{"no transit tunnels currently built", "در حال حاضر هیچ تونل عبوری ساخته نشده است"},
		{"SAM disabled", "پروتکل SAM غیرفعال است"},
		{"no sessions currently running", "در حال حاضر هیچ نشستی در حال اجرا نیست"},
		{"SAM session not found", "نشست SAM یافت نشد"},
		{"SAM Session", "نشست SAM"},
		{"Server Tunnels", "تونل‌های سرور"},
		{"Client Forwards", "انتقال‌های کاربر"},
		{"Server Forwards", "انتقال‌های سرور"},
		{"Unknown page", "برگه ناشناخته"},
		{"Invalid token", "توکن نامعتبر"},
		{"SUCCESS", "انجام شد"},
		{"Stream closed", "ارتباط بسته شد"},
		{"Stream not found or already was closed", "ارتباط پیدا نشد یا پیش‌تر بسته شده"},
		{"Destination not found", "مقصد یافت نشد"},
		{"StreamID can't be null", "StreamID نمی‌تواند خالی باشد"},
		{"Return to destination page", "بازگشت به برگه مقصد"},
		{"You will be redirected in %d seconds", "شما تا %d ثانیه دیگر به برگه دیگری منتقل خواهید شد"},
		{"LeaseSet expiration time updated", "زمان انقضای LeaseSet به‌روز شد"},
		{"LeaseSet is not found or already expired", "LeaseSet پیدا نشد یا پیش‌تر منقضی شده است"},
		{"Transit tunnels count must not exceed %d", "تعداد تونل‌های عبوری نباید از %d بیشتر باشد"},
		{"Back to commands list", "بازگشت به فهرست فرمان‌ها"},
		{"Register at reg.i2p", "ثبت در reg.i2p"},
		{"Description", "شرح"},
		{"A bit information about service on domain", "اطلاعات کوتاه درباره سرویس روی دامنه"},
		{"Submit", "ارسال"},
		{"Domain can't end with .b32.i2p", "دامنه نمی‌تواند با پسوند b32.i2p. به پایان برسد"},
		{"Domain must end with .i2p", "دامنه باید با پسوند i2p. به پایان برسد"},
		{"Unknown command", "فرمان ناشناخته"},
		{"Command accepted", "فرمان پذیرفته شد"},
		{"Proxy error", "خطای پروکسی"},
		{"Proxy info", "اطلاعات پروکسی"},
		{"Proxy error: Host not found", "خطای پروکسی: میزبان یافت نشد"},
		{"Remote host not found in router's addressbook", "میزبان راه دور در دفترچه آدرس روتر یافت نشد"},
		{"You may try to find this host on jump services below", "می‌توانید این میزبان را در سرویس‌های Jump زیر پیدا کنید"},
		{"Invalid request", "درخواست نامعتبر"},
		{"Proxy unable to parse your request", "پروکسی نمی‌تواند درخواست شما را پردازش کند"},
		{"Addresshelper is not supported", "Addresshelper پشتیبانی نمی‌شود"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "میزبان %s <font color=red> پیش‌تر در دفترچه آدرس روتر موجود است </font>. <b>هشدار: منبع این URL ممکن است خطرناک باشد!</b> برای به‌روزرسانی رکورد اینجا کلیک کنید: <a href=\"%s%s%s&update=true\">ادامه</a>."},
		{"Addresshelper forced update rejected", "به‌روزرسانی اجباری Addresshelper رد شد"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "برای اضافه کردن میزبان <b>%s</b> به دفترچه آدرس روتر، اینجا کلیک کنید: <a href=\"%s%s%s\">ادامه</a>."},
		{"Addresshelper request", "درخواست AddressHelper"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "میزبان %s از طریق AddressHelper به دفترچه آدرس روتر اضافه شد. برای ادامه اینجا کلیک کنید: <a href=\"%s\"> ادامه</a>."},
		{"Addresshelper adding", "Addresshelper در حال افزودن"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "میزبان %s <font color=red> قبلاً در دفترچه آدرس روتر موجود است</font>. برای به‌روزرسانی رکورد اینجا کلیک کنید: <a href=\"%s%s%s&update=true\">ادامه</a>."},
		{"Addresshelper update", "به‌روزرسانی Addresshelper"},
		{"Invalid request URI", "نشانی درخواست نامعتبر است"},
		{"Can't detect destination host from request", "نمی‌توان میزبان مقصد را از درخواست تشخیص داد"},
		{"Outproxy failure", "خطای Outproxy"},
		{"Bad outproxy settings", "تنظیمات Outproxy نادرست است"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "میزبان %s داخل شبکه I2P نیست، و Outproxy نیز فعال نیست"},
		{"Unknown outproxy URL", "نشانی Outproxy ناشناخته است"},
		{"Cannot resolve upstream proxy", "نمی‌توان پروکسی بالادستی را پیدا کند"},
		{"Hostname is too long", "نام میزبان خیلی طولانی است"},
		{"Cannot connect to upstream SOCKS proxy", "نمی‌توان به پروکسی SOCKS بالادست متصل شد"},
		{"Cannot negotiate with SOCKS proxy", "امکان برقراری ارتباط با پروکسی SOCKS وجود ندارد"},
		{"CONNECT error", "خطای اتصال"},
		{"Failed to connect", "اتصال برقرار نشد"},
		{"SOCKS proxy error", "خطای پروکسی SOCKS"},
		{"Failed to send request to upstream", "ارسال درخواست به بالادست ناموفق بود"},
		{"No reply from SOCKS proxy", "هیچ پاسخی از پروکسی SOCKS دریافت نشد"},
		{"Cannot connect", "اتصال برقرار نمی‌شود"},
		{"HTTP out proxy not implemented", "پروکسی خروجی HTTP پیاده‌سازی نشده است"},
		{"Cannot connect to upstream HTTP proxy", "نمی‌توان به پروکسی HTTP بالادست متصل شد"},
		{"Host is down", "میزبان در دسترس نیست"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "نمی‌توان اتصال به میزبان درخواست‌شده برقرار کرد. ممکن است میزبان خاموش باشد. لطفاً بعداً دوباره تلاش کنید."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d روز", "%d روز"}},
		{"%d hours", {"%d ساعت", "%d ساعت"}},
		{"%d minutes", {"%d دقیقه", "%d دقیقه"}},
		{"%d seconds", {"%d ثانیه", "%d ثانیه"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
