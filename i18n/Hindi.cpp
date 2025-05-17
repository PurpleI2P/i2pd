/*
* Copyright (c) 2025, The PurpleI2P Project
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

// Hindi localization file

namespace i2p
{
namespace i18n
{
namespace hindi // language namespace
{
	// language name in lowercase
	static std::string language = "hindi";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	// Right to Left language?
	static bool rtl = false;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f कीबी"},
		{"%.2f MiB", "%.2f मीबी"},
		{"%.2f GiB", "%.2f जीबी"},
		{"building", "निर्माण"},
		{"failed", "विफल"},
		{"expiring", "समाप्त होना"},
		{"established", "स्थापित"},
		{"unknown", "अज्ञात"},
		{"exploratory", "अन्वेषणात्मक"},
		{"Purple I2P Webconsole", "पर्पल I2P वेब कंसोल"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> वेब कंसोल"},
		{"Main page", "मुख्य पृष्ठ"},
		{"Router commands", "राउटर आदेश"},
		{"Local Destinations", "स्थानीय गंतव्य"},
		{"LeaseSets", "पट्ट समुच्चय"},
		{"Tunnels", "सुरंग"},
		{"Transit Tunnels", "संचरण सुरंगें"},
		{"Transports", "परिवहन"},
		{"I2P tunnels", "I2P सुरंगें"},
		{"SAM sessions", "SAM सत्र"},
		{"ERROR", "त्रुटि"},
		{"OK", "ठीक है"},
		{"Testing", "परीक्षण"},
		{"Firewalled", "फायरवॉल"},
		{"Unknown", "अज्ञात"},
		{"Proxy", "प्रॉक्सी"},
		{"Mesh", "जाली"},
		{"Clock skew", "घड़ी संकेत विचलन"},
		{"Offline", "ऑफलाइन"},
		{"Symmetric NAT", "सममितीय NAT"},
		{"Full cone NAT", "पूर्णकोण NAT"},
		{"No Descriptors", "कोई वर्णनकर्त्तृ नहीं हैं"},
		{"Uptime", "संचालन समय"},
		{"Network status", "संपर्क स्थिति"},
		{"Network status v6", "संपर्क स्थिति v6"},
		{"Stopping in", "में अवसान प्रारंभ हो रहा है"},
		{"Family", "परिवार"},
		{"Tunnel creation success rate", "सुरंग निर्माण सफलता दर"},
		{"Total tunnel creation success rate", "कुल सुरंग निर्माण सफलता दर"},
		{"Received", "प्राप्त हुआ"},
		{"%.2f KiB/s", "%.2f कीबी/से"},
		{"Sent", "प्रेषित"},
		{"Transit", "संचरण"},
		{"Data path", "डेटा पथ"},
		{"Hidden content. Press on text to see.", "सामग्री छिपाई गई है। देखने हेतु पाठ पर दबाएँ।"},
		{"Router Ident", "राउटर परिचय"},
		{"Router Family", "राउटर परिवार"},
		{"Router Caps", "राउटर कैप्स"},
		{"Version", "संस्करण"},
		{"Our external address", "हमारा बाह्य पता"},
		{"supported", "समर्थित"},
		{"Routers", "राउटर"},
		{"Floodfills", "पूर्णक संवाहक"},
		{"Client Tunnels", "क्लाइंट सुरंगें"},
		{"Services", "सेवाएँ"},
		{"Enabled", "सक्षम है"},
		{"Disabled", "निष्क्रिय है"},
		{"Encrypted B33 address", "कूटलिखित B33 पता"},
		{"Address registration line", "पता पंजीकरण पंक्ति"},
		{"Domain", "डोमेन"},
		{"Generate", "सृजित करें"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>नोट:</b> परिणाम स्ट्रिंग का उपयोग केवल 2LD डोमेनों (जैसे example.i2p) को रजिस्टर करने के लिए किया जा सकता है। सबडोमेन रजिस्टर करने के लिए कृपया i2pd-tools का उपयोग करें।"},
		{"Address", "पता"},
		{"Type", "प्रकार"},
		{"EncType", "कूट प्रकार"},
		{"Expire LeaseSet", "पट्ट समुच्चय का अवसान करें"},
		{"Inbound tunnels", "आगमनशील सुरंगें"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "प्रस्थानशील सुरंगें"},
		{"Tags", "चिन्हित"},
		{"Incoming", "आगामी"},
		{"Outgoing", "निर्गामी"},
		{"Destination", "गंतव्य"},
		{"Amount", "मात्रा"},
		{"Incoming Tags", "आगामी चिन्हित"},
		{"Tags sessions", "चिन्हित सत्र OR सत्र को चिन्हित करें"},
		{"Status", "स्थिति"},
		{"Local Destination", "स्थानीय गंतव्य"},
		{"Streams", "धाराएँ"},
		{"Close stream", "प्रवाह समाप्त करें"},
		{"Such destination is not found", "ऐसा गंतव्य नहीं मिला"},
		{"I2CP session not found", "I2CP सत्र नहीं मिला"},
		{"I2CP is not enabled", "I2CP निष्क्रिय है"},
		{"Invalid", "अमान्य"},
		{"Store type", "भण्डारगार का प्रकार"},
		{"Expires", "अवसान होता है"},
		{"Non Expired Leases", "अनवसित पट्ट"},
		{"Gateway", "प्रवेशद्वार"},
		{"TunnelID", "सुरंग ID"},
		{"EndDate", "समाप्ति तिथि"},
		{"floodfill mode is disabled", "पूर्णक संवाहक विधि निष्क्रिय है"},
		{"Queue size", "क्यू आकार"},
		{"Run peer test", "सहकर्मी परीक्षण चलाएँ"},
		{"Reload tunnels configuration", "सुरंग विन्यास पुनः लोड करें"},
		{"Decline transit tunnels", "संचरण सुरंगों को अस्वीकार करें"},
		{"Accept transit tunnels", "संचरण सुरंगों को स्वीकार करें"},
		{"Cancel graceful shutdown", "सौम्य अवसान निरस्त करें"},
		{"Start graceful shutdown", "सौम्य समापन प्रारंभ करें"},
		{"Force shutdown", "बाध्य अवसान"},
		{"Reload external CSS styles", "बाह्य CSS शैलियों को पुनः लोड करें"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>टिप्पणी:</b> यहाँ किए गए कोई भी क्रियाएँ स्थायी नहीं हैं और आपके विन्यास संचिका में कोई परिवर्तन नहीं करतीं।"},
		{"Logging level", "लॉगिंग स्तर"},
		{"Transit tunnels limit", "संचरण सुरंगों की सीमा"},
		{"Change", "बदलना"},
		{"Change language", "भाषा बदलें"},
		{"no transit tunnels currently built", "संचरण सुरंगों का निर्माण नहीं हुआ है"},
		{"SAM disabled", "SAM निष्क्रिय है"},
		{"no sessions currently running", "वर्तमान में कोई सत्र सक्रिय नहीं है"},
		{"SAM session not found", "SAM सत्र नहीं मिला"},
		{"SAM Session", "SAM सत्र"},
		{"Server Tunnels", "सर्वर सुरंग"},
		{"Client Forwards", "क्लाइंट फॉरवर्ड्स"},
		{"Server Forwards", "सर्वर फॉरवर्ड्स"},
		{"Unknown page", "अज्ञात पृष्ठ"},
		{"Invalid token", "अमान्य टोकन"},
		{"SUCCESS", "सफलता"},
		{"Stream closed", "प्रवाह समाप्त हो गया है"},
		{"Stream not found or already was closed", "प्रवाह प्राप्त नहीं हुआ अथवा इसका पूर्व में ही समापन हो चुका है"},
		{"Destination not found", "गंतव्य नहीं मिला"},
		{"StreamID can't be null", "प्रवाह ID शून्य नहीं हो सकता है"},
		{"Return to destination page", "गंतव्य पृष्ठ पर पुनः वापस जाएँ"},
		{"You will be redirected in %d seconds", "आपको %d सेकंड में पुनर्निर्देशित किया जाएगा"},
		{"LeaseSet expiration time updated", "पट्ट समुच्चय की अवसान समय को अद्यतित किया गया है"},
		{"LeaseSet is not found or already expired", "पट्ट समुच्चय प्राप्त नहीं हुआ या इसका पूर्वमेव अवसान हो चुका है"},
		{"Transit tunnels count must not exceed %d", "संचरण सुरंगों की संख्या %d से अधिक नहीं होनी चाहिए"},
		{"Back to commands list", "आदेश सूची पर पुनः लौटें"},
		{"Register at reg.i2p", "reg.i2p पर पंजीकरण करें"},
		{"Description", "विवरण"},
		{"A bit information about service on domain", "डोमेन पर सेवा से संबंधित थोड़ी जानकारी"},
		{"Submit", "प्रस्तुत करें"},
		{"Domain can't end with .b32.i2p", "डोमेन का अंत .b32.i2p से नहीं हो सकता"},
		{"Domain must end with .i2p", "डोमेन का अंत .i2p से होना आवश्यक है"},
		{"Unknown command", "अज्ञात आदेश"},
		{"Command accepted", "आदेश स्वीकार किया गया"},
		{"Proxy error", "प्रॉक्सी त्रुटि"},
		{"Proxy info", "प्रॉक्सी जानकारी"},
		{"Proxy error: Host not found", "प्रॉक्सी त्रुटि: होस्ट नहीं मिला"},
		{"Remote host not found in router's addressbook", "राउटर की पता पुस्तक में दूरस्थ होस्ट नहीं मिला"},
		{"You may try to find this host on jump services below", "आप नीचे दिए गए जंप सेवाओं में इस होस्ट को खोजने की कोशिश कर सकते हैं"},
		{"Invalid request", "अमान्य अनुरोध"},
		{"Proxy unable to parse your request", "प्रॉक्सी आपके अनुरोध को विश्लेषित करने में असमर्थ है"},
		{"Addresshelper is not supported", "Addresshelper समर्थित नहीं है"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "होस्ट %s पहले से ही राउटर की पता-पुस्तिका में <font color=red>उपस्थित है</font>। <b>सावधान रहें: इस URL का स्रोत हानिकारक हो सकता है!</b> अभिलेख को अद्यतन करने हेतु यहाँ क्लिक करें: <a href=\"%s%s%s&update=true\">जारी रखें</a>।"},
		{"Addresshelper forced update rejected", "Addresshelper का जबरन अद्यतन अस्वीकृत किया गया"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "राउटर की पता-पुस्तिका में होस्ट <b>%s</b> को जोड़ने हेतु, कृपया यहाँ क्लिक करें: <a href=\"%s%s%s\">जारी रखें</a>।"},
		{"Addresshelper request", "Addresshelper अनुरोध"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "सहायक से होस्ट %s राउटर की पता-पुस्तिका में जोड़ दिया गया है। आगे बढ़ने हेतु यहाँ क्लिक करें: <a href=\"%s\">जारी रखें</a>।"},
		{"Addresshelper adding", "Addresshelper जोड़ना"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "होस्ट %s पहले से ही राउटर की पता-पुस्तिका में <font color=red>उपस्थित है</font>। अभिलेख को अद्यतन करने हेतु यहाँ क्लिक करें: <a href=\"%s%s%s&update=true\">जारी रखें</a>।"},
		{"Addresshelper update", "Addresshelper अद्यतन करना"},
		{"Invalid request URI", "अमान्य अनुरोध URI"},
		{"Can't detect destination host from request", "अनुरोध से गंतव्य होस्ट का पता नहीं लगा सकते"},
		{"Outproxy failure", "आउटप्रॉक्सी विफलता"},
		{"Bad outproxy settings", "गलत आउटप्रॉक्सी सेटिंग्स"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "होस्ट %s I2P नेटवर्क के भीतर नहीं है, लेकिन आउटप्रॉक्सी सक्षम नहीं है"},
		{"Unknown outproxy URL", "अज्ञात आउटप्रॉक्सी URL"},
		{"Cannot resolve upstream proxy", "ऊर्ध्वधारा प्रॉक्सी का समाधान नहीं किया जा सका"},
		{"Hostname is too long", "होस्टनाम अत्यधिक लंबा है"},
		{"Cannot connect to upstream SOCKS proxy", "उर्ध्वधारा SOCKS प्रॉक्सी से संपर्क स्थापित नहीं हो पा रहा है"},
		{"Cannot negotiate with SOCKS proxy", "SOCKS प्रॉक्सी के साथ समन्वयन स्थापित नहीं किया जा सका"},
		{"CONNECT error", "संपर्क त्रुटि"},
		{"Failed to connect", "संपर्क स्थापित करने में विफल"},
		{"SOCKS proxy error", "SOCKS प्रॉक्सी त्रुटि"},
		{"Failed to send request to upstream", "ऊर्ध्ववाहिनी को अनुरोध प्रेषित करने में विफलता हुई"},
		{"No reply from SOCKS proxy", "SOCKS प्रॉक्सी से कोई प्रत्युत्तर प्राप्त नहीं हुआ"},
		{"Cannot connect", "संपर्क नहीं हो पा रहा है"},
		{"HTTP out proxy not implemented", "HTTP आउट प्रॉक्सी कार्यान्वित नहीं किया गया है"},
		{"Cannot connect to upstream HTTP proxy", "उर्ध्वधारा HTTP प्रॉक्सी से संपर्क स्थापित नहीं हो पा रहा है"},
		{"Host is down", "होस्ट अनुपलब्ध है"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "अनुरोधित होस्ट से संपर्क स्थापित नहीं किया जा सका। संभवतः वह सक्रिय नहीं है। कृपया बाद में पुनः प्रयास करें।"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d दिन", "%d दिन"}},
		{"%d hours", {"%d घंटा", "%dघंटे"}},
		{"%d minutes", {"%d मिनट", "%d मिनट"}},
		{"%d seconds", {"%d सेकंड", "%d सेकंड"}},
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
