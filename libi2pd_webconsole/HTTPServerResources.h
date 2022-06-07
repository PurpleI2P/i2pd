/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef HTTP_SERVER_RESOURCES_H__
#define HTTP_SERVER_RESOURCES_H__

namespace i2p
{
namespace http
{
	const std::string itoopieFavicon =
		"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx"
		"jwv8YQUAAAAJcEhZcwAALiIAAC4iAari3ZIAAAAHdElNRQfgCQsUNSZrkhi1AAAAGXRFWHRTb2Z0"
		"d2FyZQBwYWludC5uZXQgNC4wLjEyQwRr7AAAAoJJREFUOE9jwAUqi4Q1oEwwcDTV1+5sETaBclGB"
		"vb09C5QJB6kWpvFQJoOCeLC5kmjEHCgXE2SlyETLi3h6QrkM4VL+ssWSCZUgtopITLKqaOotRTEn"
		"cbAkLqAkGtOqLBLVAWLXyWSVFkkmRiqLxuaqiWb/VBYJMAYrwgckJY25VEUzniqKhjU2y+RtCRSP"
		"6lUXy/1jIBV5tlYxZUaFVMq2NInwIi9hO8fSfOEAqDZUoCwal6MulvOvyS7gi69K4j9zxZT/m0ps"
		"/28ptvvvquXXryIa7QYMMdTwqi0WNtVi0GIDseXl7TnUxFKfnGlxAGp0+D8j2eH/8Ub7/9e7nf7X"
		"+Af/B7rwt6pI0h0l0WhQADOC9DBkhSirpImHNVZKp24ukkyoshGLnN8d5fA/y13t/44Kq/8hlnL/"
		"z7fZ/58f6vcxSNpbVUVFhV1RLNBVTsQzVYZPSwhsCAhkiIfpNMrkbO6TLf071Sfk/5ZSi/+7q6z/"
		"P5ns+v9mj/P/CpuI/20y+aeNGYxZoVoYGmsF3aFMBAAZlCwftnF9ke3//bU2//fXWP8/UGv731Am"
		"+V+DdNblSqnUYqhSTKAiYSOqJBrVqiaa+S3UNPr/gmyH/xuKXf63hnn/B8bIP0UxHfEyyeSNQKVM"
		"EB1AEB2twhcTLp+gIBJUoyKasEpVJHmqskh8qryovUG/ffCHHRU2q/Tk/YuB6eGPsbExa7ZkpLu1"
		"oLEcVDtuUCgV1w60rQzElpRUE1EVSX0BYidHiInXF4nagNhYQW60EF+ApH1ktni0A1SIITSUgVlZ"
		"JHYnlIsfzJjIp9xZKswL5YKBHL+coKJoRDaUSzoozxHVrygQU4JykQADAwAT5b1NHtwZugAAAABJ"
		"RU5ErkJggg==";

	// bundled style sheet
	const std::string internalCSS =
		":root { --main-bg-color: #fafafa; --main-text-color: #103456; --main-link-color: #894c84; --main-link-hover-color: #fafafa; }\r\n"
		"@media (prefers-color-scheme: dark) { :root { --main-bg-color: #242424; --main-text-color: #17ab5c; --main-link-color: #bf64b7; --main-link-hover-color: #000000; } }\r\n"
		"body { font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: var(--main-bg-color); color: var(--main-text-color); }\r\n"
		"a, .slide label { text-decoration: none; color: var(--main-link-color); }\r\n"
		"a:hover, .slide label:hover, button[type=submit]:hover { color: var(--main-link-hover-color); background: var(--main-link-color); }\r\n"
		"a.button { appearance: button; text-decoration: none; padding: 0 5px; border: 1px solid var(--main-link-color); }\r\n"
		".header { font-size: 2.5em; text-align: center; margin: 1em 0; color: var(--main-link-color); }\r\n"
		".wrapper { margin: 0 auto; padding: 1em; max-width: 64em; }\r\n"
		".menu { display: block; float: left; overflow: hidden; padding: 4px; max-width: 12em; white-space: nowrap; text-overflow: ellipsis ;}\r\n"
		".listitem { display: block; font-family: monospace; font-size: 1.2em; white-space: nowrap; }\r\n"
		".tableitem { font-family: monospace; font-size: 1.2em; white-space: nowrap; }\r\n"
		".content { float: left; font-size: 1em; margin-left: 2em; padding: 4px; max-width: 50em; overflow: auto; }\r\n"
		".tunnel.established { color: #56B734; }\r\n"
		".tunnel.expiring { color: #D3AE3F; }\r\n"
		".tunnel.failed { color: #D33F3F; }\r\n"
		".tunnel.building { color: #434343; }\r\n"
		"caption { font-size: 1.5em; text-align: center; color: var(--main-link-color); }\r\n"
		"table { display: table; border-collapse: collapse; text-align: center; }\r\n"
		"table.extaddr { text-align: left; }\r\n"
		"table.services { width: 100%; }\r\n"
		"textarea { background-color: var(--main-bg-color); color: var(--main-text-color); word-break: break-all; }\r\n"
		".streamdest { width: 120px; max-width: 240px; overflow: hidden; text-overflow: ellipsis; }\r\n"
		".slide div.slidecontent, .slide [type=\"checkbox\"] { display: none; }\r\n"
		".slide [type=\"checkbox\"]:checked ~ div.slidecontent { display: block; margin-top: 0; padding: 0; }\r\n"
		".disabled { color: #D33F3F; }\r\n"
		".enabled { color: #56B734; }\r\n"
		"button[type=submit] { background-color: transparent; color: var(--main-link-color); text-decoration: none;\r\n"
		"	padding: 5px; border: 1px solid var(--main-link-color); font-size: 14px; }\r\n"
		"input, select, select option { background-color: var(--main-bg-color); color: var(--main-link-color); padding: 5px;\r\n"
		"	border: 1px solid var(--main-link-color); font-size: 14px; }\r\n"
		"input:focus, select:focus, select option:focus { outline: none; }\r\n"
		"input[type=number]::-webkit-inner-spin-button { -webkit-appearance: none; }\r\n"
		"@media screen and (max-width: 1150px) { /* adaptive style */\r\n"
		"	.wrapper { max-width: 58em; }\r\n"
		"	.content { max-width: 40em; }\r\n"
		"}\r\n"
		"@media screen and (max-width: 980px) { body { font: 100%/1.2em sans-serif; padding: 1.2em 0 0 0; }\r\n"
		"	.menu { width: 100%; max-width: unset; display: block; float: none; position: unset; font-size: 16px; text-align: center; }\r\n"
		"	.menu a, .commands a { display: inline-block; padding: 4px; }\r\n"
		"	.content { float: none; margin-left: unset; margin-top: 16px; max-width: 100%; width: 100%; text-align: center; }\r\n"
		"	a, .slide label { display: block; }\r\n"
		"	.header { margin: unset; font-size: 1.5em; }\r\n"
		"	small { display: block; }\r\n"
		"	a.button { appearance: button; text-decoration: none; margin-top: 10px; padding: 6px; border: 2px solid var(--main-link-color);\r\n"
		"		border-radius: 5px; width: -webkit-fill-available; }\r\n"
		"	input, select { width: 35%; text-align: center; padding: 5px; border: 2px solid var(--main-link-color); border-radius: 5px; font-size: 18px; }\r\n"
		"	table.extaddr { margin: auto; text-align: unset; }\r\n"
		"	textarea { width: -webkit-fill-available; height: auto; padding: 5px; border: 2px solid var(--main-link-color);\r\n"
		"		border-radius: 5px; font-size: 12px; }\r\n"
		"	button[type=submit] { padding: 5px 15px; background: transparent; border: 2px solid var(--main-link-color); cursor: pointer;\r\n"
		"		border-radius: 5px; position: relative; height: 36px; display: -webkit-inline-box; margin-top: 10px; }\r\n"
		"}\r\n"

	// for external style sheet
	std::string externalCSS;

	const std::string pageBase =
"<!DOCTYPE html> \
<html lang=\"{{ langCode }}\"> \
<head> \
	{% block head %} \
	<meta charset=\"UTF-8\"> \
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"> \
	<link rel=\"shortcut icon\" href=\"{% getFavicon() %}\"> \
	<title>{% block title %}{% endblock %} - Purple I2P Webconsole</title> \
	<style>{% getStyles() %}</style> \
	{% endblock %} \
</head> \
<body> \
	<div class=\"header\">{% tr(\"<b>i2pd</b> webconsole\") %}</div> \
	<div class=\"wrapper\"> \
		<div class=\"menu\"> \
			<a href=\"{{ webroot }}\">{% tr(\"Main page\") %}</a><br><br> \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_COMMANDS\") %}\">{% tr(\"Router commands\") %}</a><br> \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_LOCAL_DESTINATIONS\") %}\">{% tr(\"Local Destinations\") %}</a><br> \
			{% if isFloodfill %} \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_LEASESETS\") %}\">{% tr(\"LeaseSets\") %}</a><br> \
			{% endif %} \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_TUNNELS\") %}\">{% tr(\"Tunnels\") %}</a><br> \
			{% if (acceptingTunnels || transitTunnels) %} \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_TRANSIT_TUNNELS\") %}\">{% tr(\"Transit Tunnels\") %}</a><br> \
			{% endif %} \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_TRANSPORTS\") %}\">{% tr(\"Transports\") %}</a><br> \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_I2P_TUNNELS\") %}\">{% tr(\"I2P tunnels\") %}</a><br> \
			{% if samEnabled %} \
			<a href=\"{{ webroot }}?page={% getCommand(\"HTTP_PAGE_SAM_SESSIONS\") %}\">{% tr(\"SAM sessions\") %}</a><br> \
			{% endif %} \
		</div> \
		<div class=\"content\">{% block content %}{% endblock %}</div> \
	</div> \
</body> \
</html>"

	const std::string pageMain =
"{% extends \"base.html\" %} \
{% block title %}Main{% endblock %} \
{% block content %} \
	<b>{% tr(\"Uptime\") %}:</b> {% getUptime() %}<br> \
	<b>{% tr(\"Network status\") %}:</b> {% getNetworkStatus(false) %}<br> \
	{% if supportsV6 %} \
	<b>{% tr(\"Network status v6\") %}:</b> {% getNetworkStatus(true) %}<br> \
	{% endif %} \
	{% if gracefulShutdown %} \
	<b>{% tr(\"Stopping in\") %}:</b> {% getShutdownTimer() %}<br> \
	{% endif %} \
	<b>{% tr(\"Tunnel creation success rate\") %}:</b> {% getSuccessRate() %}%<br> \
	<b>{% tr(\"Received\") %}:</b> {% getInBytes() %} ({% getInBW() %} {% tr(/* tr: Kibibit/s */ \"KiB/s\") %})<br> \
	<b>{% tr(\"Sent\") %}:</b> {% getOutBytes() %} ({% getOutBW() %} {% tr(/* tr: Kibibit/s */ \"KiB/s\") %})<br> \
	<b>{% tr(\"Transit\") %}:</b> {% getTransitBytes() %} ({% getTransitBW() %} {% tr(/* tr: Kibibit/s */ \"KiB/s\") %})<br> \
	<b>{% tr(\"Data path\") %}:</b> {% getDataPath() %}<br> \
	{% if notQt || withHiddenContent %} \
	<div class=\"slide\"> \
		<label for=\"slide-info\">{% tr(\"Hidden content. Press on text to see.\") %}</label> \
		<input type=\"checkbox\" id=\"slide-info\" /> \
		<div class=\"slidecontent\"> \
			<b>{% tr(\"Router Ident\") %}:</b> {% getRI() %}<br> \
			{% if lenght(family) %} \
			<b>{% tr(\"Family\") %}:</b> {{ family }}<br> \
			{% endif %} \
			<b>{% tr(\"Router Caps\") %}:</b> {% getCaps() %}<br> \
			<b>{% tr(\"Version\") %}:</b> {{ version }}<br> \
			<b>{% tr(\"Our external address\") %}:</b><br> \
			<table class=\"extaddr\"> \
				<tbody> \
					{% for type, address in addresses %} \
					<tr><td>{{ type }}</td><td>{{ address }}</td></tr> \
					{% endfor %} \
				</tbody> \
			</table> \
		</div> \
	</div> \
	{% else %} \
	<br> \
	{% endif %} \
	<b>{% tr(\"Routers\") %}:</b> {% getNumRouter() %} \
	<b>{% tr(\"Floodfills\") %}:</b> {% getNumFloodfills() %} \
	<b>{% tr(\"LeaseSets\") %}:</b> {% getNumLeaseSets() %}<br> \
	<b>{% tr(\"Client Tunnels\") %}:</b> {% getClientTunnelsCount() %} \
	<b>{% tr(\"Transit Tunnels\") %}:</b> {% getTransitTunnelsCount() %}<br> \
	<br> \
	{% if notQt == false %} \
	<table class=\"services\"> \
		<caption>{% tr(\"Services\") %}</caption> \
		<tbody> \
			<tr> \
				<td>HTTP {% tr(\"Proxy\") %}</td> \
				<td class=\"{% if httpproxy %}enabled{% else %}disabled{% endif %}\">{% if httpproxy %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
			<tr> \
				<td>SOCKS {% tr(\"Proxy\") %}</td> \
				<td class=\"{% if socksproxy %}enabled{% else %}disabled{% endif %}\">{% if socksproxy %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
			<tr> \
				<td>BOB</td> \
				<td class=\"{% if bob %}enabled{% else %}disabled{% endif %}\">{% if bob %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
			<tr> \
				<td>SAM</td> \
				<td class=\"{% if sam %}enabled{% else %}disabled{% endif %}\">{% if sam %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
			<tr> \
				<td>I2CP</td> \
				<td class=\"{% if i2cp %}enabled{% else %}disabled{% endif %}\">{% if i2cp %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
			<tr> \
				<td>I2PControl</td> \
				<td class=\"{% if i2pcontrol %}enabled{% else %}disabled{% endif %}\">{% if i2pcontrol %}{% tr(\"Enabled\") %}{% else %}{% tr(\"Disabled\") %}{% endif %}</td> \
			</tr> \
		</tbody> \
	</table> \
{% endblock %}"

} // http
} // i2p

#endif /* HTTP_SERVER_RESOURCES_H__ */
