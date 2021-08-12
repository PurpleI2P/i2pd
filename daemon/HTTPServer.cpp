/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <iomanip>
#include <sstream>
#include <thread>
#include <memory>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Config.h"
#include "Tunnel.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "HTTP.h"
#include "LeaseSet.h"
#include "Destination.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "HTTPServer.h"
#include "Daemon.h"
#include "util.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "I18N.h"

#ifdef WIN32_APP
#include "Win32App.h"
#endif

// For image and info
#include "version.h"

namespace i2p {
namespace http {
	const std::string i2pdfavicon =
		"data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 64 64\'%3E%3Crect width=\'64\' height=\'64\' fill=\'%23313\' rx=\'5\'/%3E%3Ccircle cx=\'8\' cy=\'32\' r=\'4\' fill=\'%23ee6565\'/%3E%3Ccircle cx=\'20\' cy=\'32\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'32\' cy=\'8\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'32\' cy=\'20\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'32\' cy=\'32\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'32\' cy=\'44\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'32\' cy=\'56\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'44\' cy=\'32\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'56\' cy=\'32\' r=\'4\' fill=\'%23ee6565\'/%3E%3Ccircle cx=\'8\' cy=\'20\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'8\' cy=\'44\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'20\' cy=\'8\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'20\' cy=\'20\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'20\' cy=\'44\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'20\' cy=\'56\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'44\' cy=\'8\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'44\' cy=\'20\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'44\' cy=\'44\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'44\' cy=\'56\' r=\'4\' fill=\'%239ff39f\'/%3E%3Ccircle cx=\'56\' cy=\'20\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'56\' cy=\'44\' r=\'4\' fill=\'%23ffc95e\'/%3E%3Ccircle cx=\'8\' cy=\'8\' r=\'4\' fill=\'%23ee6565\'/%3E%3Ccircle cx=\'8\' cy=\'56\' r=\'4\' fill=\'%23ee6565\'/%3E%3Ccircle cx=\'56\' cy=\'8\' r=\'4\' fill=\'%23ee6565\'/%3E%3Ccircle cx=\'56\' cy=\'56\' r=\'4\' fill=\'%23ee6565\'/%3E%3C/svg%3E";

	// Bundled style
	const std::string internalCSS =
		"<style>\r\n"
		"  :root{--bodyfont:Open Sans,Noto Sans,Ubuntu,Segoe UI,sans-serif;\r\n"
		"  --monospaced:Droid Sans Mono,Noto Mono,Lucida Console,DejaVu Sans Mono,monospace;\r\n"
		"  --logo:url(\"data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 58 16\'%3E%3Cg fill=\'%23525\'%3E%3Ccircle cx=\'3.1\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'3.1\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'3.1\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'3.1\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'13.5\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'13.5\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'13.5\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'13.5\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'16.9\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'20.4\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'23.8\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'27.3\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'27.3\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'27.3\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'27.3\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'34.2\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'34.2\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'37.6\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'41.1\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'41.1\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'41.1\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'41.1\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'48\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'48\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'51.4\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'51.4\' cy=\'13.2\' r=\'1.2\'/%3E%3C/g%3E%3Cg fill=\'%23f0f\'%3E%3Ccircle cx=\'6.6\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'6.6\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'6.6\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'6.6\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'10\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'10\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'10\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'10\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'16.9\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'16.9\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'16.9\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'20.4\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'20.4\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'20.4\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'23.8\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'23.8\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'23.8\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'30.7\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'30.7\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'30.7\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'30.7\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'34.2\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'34.2\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'37.6\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'37.6\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'37.6\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'44.5\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'44.5\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'44.5\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'44.5\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'48\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'48\' cy=\'13.2\' r=\'1.2\'/%3E%3Ccircle cx=\'51.4\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'51.4\' cy=\'9.7\' r=\'1.2\'/%3E%3C/g%3E%3Cg fill=\'%23525\'%3E%3Ccircle cx=\'54.9\' cy=\'2.8\' r=\'1.2\'/%3E%3Ccircle cx=\'54.9\' cy=\'6.3\' r=\'1.2\'/%3E%3Ccircle cx=\'54.9\' cy=\'9.7\' r=\'1.2\'/%3E%3Ccircle cx=\'54.9\' cy=\'13.2\' r=\'1.2\'/%3E%3C/g%3E%3C/svg%3E\");\r\n"
		"  --dropdown:url(\"data:image/svg+xml,%3Csvg viewBox=\'0 0 64 64\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cpath d=\'m5.29 17.93 26.71 28.14 26.71-28.14\' fill=\'none\' stroke=\'%23894C84\' stroke-linecap=\'round\' stroke-linejoin=\'round\' stroke-width=\'10\'/%3E%3C/svg%3E\");\r\n"
		"  --dropdown_hover:url(\"data:image/svg+xml,%3Csvg viewBox=\'0 0 64 64\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cpath d=\'m5.29 17.93 26.71 28.14 26.71-28.14\' fill=\'none\' stroke=\'%23fafafa\' stroke-linecap=\'round\' stroke-linejoin=\'round\' stroke-width=\'10\'/%3E%3C/svg%3E\");\r\n"
		"  --yes:url(\"data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 64 64\'%3E%3Cpath fill=\'%2371c837\' d=\'M55.9 8.6a4.3 4.3 0 00-3 1.3l-31 30.8L11.3 30a4.4 4.4 0 00-6 0l-4 4.2a4.4 4.4 0 000 6L19 57.7a4.4 4.4 0 006 0l37.8-37.9a4.4 4.4 0 000-6l-4-4a4.3 4.3 0 00-3-1.3z\'/%3E%3C/svg%3E\");\r\n"
		"  --no:url(\"data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 64 64\'%3E%3Cpath fill=\'red\' d=\'M9.7 0c-1 0-2.1.4-3 1.2L1.3 7a4.2 4.2 0 000 5.8L20.6 32 1.3 51.3a4.2 4.2 0 000 5.9l5.6 5.6a4.2 4.2 0 005.9 0L32 43.5l19.2 19.3a4.2 4.2 0 005.9 0l5.6-5.6a4.2 4.2 0 000-5.9L43.5 32l19.2-19.3a4.1 4.1 0 000-5.9l-5.6-5.6a4.2 4.2 0 00-5.8 0L32 20.5 12.6 1.2A4.2 4.2 0 009.7 0z\'/%3E%3C/svg%3E\");\r\n"
		"  --info:url(\"data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 64 64\'%3E%3Cpath fill=\'%23fcf\' stroke=\'%23313\' d=\'M31.4 3a28.8 28.8 0 00-1.6.1 28.8 28.8 0 00-26.6 29 28.8 28.8 0 1057.6 0A28.8 28.8 0 0031.4 3zm.6 9.3a4.5 4.5 0 014.5 4.5 4.5 4.5 0 01-4.5 4.4 4.5 4.5 0 01-4.5-4.4 4.5 4.5 0 014.5-4.5zm-4.5 13.1h9v26.3h-9V25.4z\'/%3E%3C/svg%3E\");\r\n"
		"  --scrollbar:#414 #101;\r\n"
		"  --ink:#dbd;\r\n"
		"  --notify:#5f5;\r\n"
		"  --page:#101;\r\n"
		"  --main-boxshadow:0 0 0 1px #000,0 0 0 3px #313,0 0 0 5px #000;\r\n"
		"  --link:#894c84;\r\n"
		"  --link_hover:#fafafa;\r\n"
		"  --border:#515;\r\n"
		"  --button-border:#313;\r\n"
		"  --button:linear-gradient(#303,#202);\r\n"
		"  --button_hover:linear-gradient(to bottom,#733f6f,#522d4f);\r\n"
		"  --button_active:linear-gradient(to bottom,#202,#303);\r\n"
		"  --active_shadow:inset 3px 3px 3px rgba(0,0,0,.6);\r\n"
		"  --hr:linear-gradient(to right,#313,#414,#313);\r\n"
		"  --highlight:inset 0 0 0 1px #101;\r\n"
		"  --tr:#180018;\r\n"
		"  --textarea:#000;\r\n"
		"  --textarea-ink:#103456;\r\n"
		"  --input_text:var(--button-border)}\r\n"
		"  html,body{min-height:100%}\r\n"
		"  html,body,textarea{scrollbar-color:var(--scrollbar)}\r\n"
		"  body{font:14pt var(--bodyfont);margin:0;padding:0;background:var(--page);color:var(--ink);line-height:1.6;position:absolute;top:0;left:0;width:100%;height:100%;text-align:center;display:table}\r\n"
		"  .header{display:none}\r\n"
		"  .wrapper{margin:0 auto;padding:5px;width:96%;display:table-cell;vertical-align:middle;text-align:center}\r\n"
		"  #main{margin:0 auto;min-width:300px;max-width:700px;font-size:85%;border:2px solid var(--border);border-spacing:1px;box-shadow:var(--main-boxshadow)}\r\n"
		"  .center,.center form{text-align:center!important}\r\n"
		"  form{margin:5px 0}\r\n"
		"  a,.slide label{text-decoration:none;color:var(--link);font-weight:600}\r\n"
		"  a{padding:1px 8px;display:inline-block;border-radius:2px}\r\n"
		"  .listitem a{padding:0}\r\n"
		"  a#home{margin:10px 0 20px;padding-bottom:40px;width:calc(100% - 20px);display:inline-block;vertical-align:top;position:relative;font-size:0;background:var(--logo) no-repeat center center / auto 40px;opacity:.5}\r\n"
		"  a#home::after{content:"";display:inline-block;width:100%;height:1px;background:var(--hr);margin:20px 0 10px;position:absolute;bottom:-20px;left:0;right:0;opacity:1}\r\n"
		"  a#home:hover{opacity:1}\r\n"
		"  a:hover,.slide label:hover,button:hover,select:hover,input[type=number]:focus{color:var(--link_hover);background:var(--link)}\r\n"
		"  a.button,button,input,select{vertical-align:middle}\r\n"
		"  select,input,button{margin:4px 2px;padding:6px 8px;font-family:var(--bodyfont);font-size:90%!important;font-weight:600;color:var(--link);border:1px solid var(--button-border);appearance:none}\r\n"
		"  a,select,button,label{cursor:pointer}\r\n"
		"  a.button,button{margin:4px 2px;padding:1px 8px 4px;min-width:64px;display:inline-block;font-size:90%!important;font-weight:700;text-align:center;text-decoration:none;border:1px solid var(--button-border);border-radius:2px;box-shadow:var(--highlight);background:var(--button);appearance:none}\r\n"
		"  button{padding:6px 12px;min-width:120px}\r\n"
		"  a.button:hover,a.button:focus{color:var(--link_hover);background:var(--button_hover)!important}\r\n"
		"  button:active,a.button:active,.slide label:active{box-shadow:var(--highlight),var(--active_shadow);background:var(--button_active)!important}\r\n"
		"  select,input[type=number]{min-width:150px;max-width:150px;box-sizing:border-box;background:var(--input_text)}\r\n"
		"  input[type=number]{box-shadow:var(--highlight),var(--active_shadow);outline:none;appearance:none}\r\n"
		"  select{padding:6px 20px 6px 8px;line-height:1.5;background:var(--dropdown) no-repeat right 8px center / 10px,var(--button);box-shadow:var(--highlight)}\r\n"
		"  select:hover,select:focus,select:active{color:var(--link_hover);background:var(--dropdown_hover) no-repeat right 8px center / 10px,var(--button_hover)}\r\n"
		"  .note{padding:15px 10px!important}\r\n"
		"  .note::before{width:24px;height:22px;display:inline-block;vertical-align:middle;background:var(--info) no-repeat center center / 16px;content:\"\"}\r\n"
		"  .notify{padding:30px 10px!important;text-align:center!important;font-size:120%;color:var(--notify)}\r\n"
		"  .notify.error{color:red}\r\n"
		"  #main tr{background:var(--tr);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}\r\n"
		"  #main th,#main td{padding:5px 12px;border:1px solid var(--button-border);box-shadow:inset 0 0 0 1px rgba(0,0,0,.6)}\r\n"
		"  #main th{padding:6px 12px;font-weight:700;font-size:105%;background:linear-gradient(to bottom,#101,#000)}\r\n"
		"  #main table th{font-size:80%}\r\n"
		"  #main td:first-child{width:50%;text-align:right;font-weight:600}\r\n"
		"  #main td:last-child{text-align:left}\r\n"
		"  #navlinks{padding:0 4px 12px!important}\r\n"
		"  .enabled,.disabled{font-size:0}\r\n"
		"  #main .enabled{background:var(--yes) no-repeat left 12px center / 10px}\r\n"
		"  #main .disabled{background:var(--no) no-repeat left 12px center / 10px}\r\n"
		"  .sensitive{filter:blur(8px);display:inline-block!important;max-width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.05;font-size:75%}\r\n"
		"  .sensitive:hover,td:active .sensitive{max-width:300px;white-space:pre-wrap;word-break:break-all;filter:blur(0)}\r\n"
		"  .arrowright,.arrowleft,.arrowleftright{font-size:200%!important;line-height:0}\r\n"
		"  .listitem{padding:1px 0;display:block;width:100%;font-family:var(--monospaced);font-size:80%;white-space:nowrap;border-bottom:1px dotted var(--button-border)}\r\n"
		"  .listitem:last-child{border-bottom:none}\r\n"
		"  .tableitem{font-family:var(--monospaced);font-size:90%;white-space:nowrap}\r\n"
		"  .tunnel.established{color:#56B734}\r\n"
		"  .tunnel.expiring{color:#D3AE3F}\r\n"
		"  .tunnel.failed{color:#D33F3F}\r\n"
		"  .tunnel.building{color:#434343}\r\n"
		"  caption{font-size:1.5em;text-align:center;color:var(--link)}\r\n"
		"  table{display:table;border-collapse:collapse;text-align:center}\r\n"
		"  table.extaddr{text-align:left}\r\n"
		"  table.services{width:100%}\r\n"
		"  textarea{margin:4px 0;width:calc(100% - 6px);resize:vertical;word-break:break-all;color:var(--textarea-ink);border:1px solid var(--button-border);background:var(--textarea)}\r\n"
		"  .streamdest{width:120px;max-width:240px;overflow:hidden;text-overflow:ellipsis}\r\n"
		"  .slide div.slidecontent,.slide [type=checkbox]{display:none}\r\n"
		"  .slide [type=checkbox]:checked ~ div.slidecontent{margin-top:0;padding:0;display:block}\r\n"
		"  .disabled{color:#D33F3F}\r\n"
		"  .enabled{color:#56B734}\r\n"
		"  .nopadding{padding:0!important}\r\n"
		"  .slide{margin:0 0 8px}\r\n"
		"  .slide .listitem:last-child{margin-bottom:8px!important}\r\n"
		"  .slide label{margin:8px auto;padding:4px 0;width:calc(100% - 16px);display:block;border:1px solid var(--button-border);box-shadow:var(--highlight);background:var(--button);box-sizing:border-box}\r\n"
		"  .slide label:hover{color:var(--link_hover);background:var(--button_hover)}\r\n"
		"  @media screen and (max-width: 1000px) {body{font-size:13pt!important}.listitem{font-size:90%}a{padding:1px 3px}}\r\n"
		"  @media screen and (-webkit-min-device-pixel-ratio: 1.5) {body{font-size:12pt!important}}\r\n"
		"  @media screen and (min-width: 1200px) {#main{width:700px}}\r\n"
		"  @media screen and (min-width: 1200px) and (min-height: 600px) {.wrapper{padding:2%}}\r\n"
		"</style>\r\n";

	// for external style sheet
	std::string externalCSS;

	static void LoadExtCSS ()
	{
		std::stringstream s;
		std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
		if (i2p::fs::Exists(styleFile)) {
			std::ifstream f(styleFile, std::ifstream::binary);
			s << f.rdbuf();
			externalCSS = s.str();
		}
	}

	static void GetStyles (std::stringstream& s)
	{
		if (externalCSS.length() != 0)
			s << "<style>\r\n" << externalCSS << "</style>\r\n";
		else
			s << internalCSS;
	}

	const char HTTP_PAGE_TUNNELS[] = "tunnels";
	const char HTTP_PAGE_TRANSIT_TUNNELS[] = "transit_tunnels";
	const char HTTP_PAGE_TRANSPORTS[] = "transports";
	const char HTTP_PAGE_LOCAL_DESTINATIONS[] = "local_destinations";
	const char HTTP_PAGE_LOCAL_DESTINATION[] = "local_destination";
	const char HTTP_PAGE_I2CP_LOCAL_DESTINATION[] = "i2cp_local_destination";
	const char HTTP_PAGE_SAM_SESSIONS[] = "sam_sessions";
	const char HTTP_PAGE_SAM_SESSION[] = "sam_session";
	const char HTTP_PAGE_I2P_TUNNELS[] = "i2p_tunnels";
	const char HTTP_PAGE_COMMANDS[] = "commands";
	const char HTTP_PAGE_LEASESETS[] = "leasesets";
	const char HTTP_COMMAND_ENABLE_TRANSIT[] = "enable_transit";
	const char HTTP_COMMAND_DISABLE_TRANSIT[] = "disable_transit";
	const char HTTP_COMMAND_SHUTDOWN_START[] = "shutdown_start";
	const char HTTP_COMMAND_SHUTDOWN_CANCEL[] = "shutdown_cancel";
	const char HTTP_COMMAND_SHUTDOWN_NOW[] = "terminate";
	const char HTTP_COMMAND_RUN_PEER_TEST[] = "run_peer_test";
	const char HTTP_COMMAND_RELOAD_CONFIG[] = "reload_config";
	const char HTTP_COMMAND_LOGLEVEL[] = "set_loglevel";
	const char HTTP_COMMAND_KILLSTREAM[] = "closestream";
	const char HTTP_COMMAND_LIMITTRANSIT[] = "limittransit";
	const char HTTP_COMMAND_GET_REG_STRING[] = "get_reg_string";
	const char HTTP_COMMAND_SETLANGUAGE[] = "setlanguage";
	const char HTTP_COMMAND_RELOAD_CSS[] = "reload_css";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_PARAM_ADDRESS[] = "address";

	static std::string ConvertTime (uint64_t time)
	{
		lldiv_t divTime = lldiv(time, 1000);
		time_t t = divTime.quot;
		struct tm *tm = localtime(&t);
		char date[128];
		snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d.%03lld", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, divTime.rem);
		return date;
	}

	static void ShowUptime (std::stringstream& s, int seconds)
	{
		int num;

		if ((num = seconds / 86400) > 0) {
			s << num << " " << tr("day", "days", num) << ", ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << num << " " << tr("hour", "hours", num) << ", ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << num << " " << tr("minute", "minutes", num) << ", ";
			seconds -= num * 60;
		}
		s << seconds << " " << tr("second", "seconds", seconds);
	}

	static void ShowTraffic (std::stringstream& s, uint64_t bytes)
	{
		s << std::fixed << std::setprecision(0);
		auto numKBytes = (double) bytes / 1024;
		if (numKBytes < 1) {
			s << std::fixed << std::setprecision(2);
			s << numKBytes * 1024 << "&#8239;" << tr(/* tr: Byte */ "B");
		} else if (numKBytes < 1024) {
			s << numKBytes << "&#8239;" << tr(/* tr: Kibibit */ "K");
		} else if (numKBytes < 1024 * 1024) {
			s << std::fixed << std::setprecision(1);
			s << numKBytes / 1024 << "&#8239;" << tr(/* tr: Mebibit */ "M");
		} else if (numKBytes < 1024 * 1024 * 1024) {
			s << std::fixed << std::setprecision(2);
			s << numKBytes / 1024 / 1024 << "&#8239;" << tr(/* tr: Gibibit */ "G");
		} else {
			s << numKBytes / 1024 / 1024 / 1024 << "&#8239;" << tr(/* tr: Tibibit */ "T");
		}
	}

	static void ShowTunnelDetails (std::stringstream& s, enum i2p::tunnel::TunnelState eState, bool explr, double bytes)
	{
		std::string state, stateText;
		switch (eState) {
			case i2p::tunnel::eTunnelStateBuildReplyReceived :
			case i2p::tunnel::eTunnelStatePending     : state = "building";    break;
			case i2p::tunnel::eTunnelStateBuildFailed :
			case i2p::tunnel::eTunnelStateTestFailed  :
			case i2p::tunnel::eTunnelStateFailed      : state = "failed";      break;
			case i2p::tunnel::eTunnelStateExpiring    : state = "expiring";    break;
			case i2p::tunnel::eTunnelStateEstablished : state = "established"; break;
			default: state = "unknown"; break;
		}

		if      (state == "building")    stateText = tr("building");
		else if (state == "failed")      stateText = tr("failed");
		else if (state == "expiring")    stateText = tr("expiring");
		else if (state == "established") stateText = tr("established");
		else stateText = tr("unknown");

		s << "<span class=\"tunnel " << state << ((explr) ? " exploratory" : "")
		  << "\" data-tooltip=\"" << stateText << ((explr) ? " (" + tr("exploratory") + ")" : "") << "\">"
		  << stateText << ((explr) ? " (" + tr("exploratory") + ")" : "") << "</span>";
		s << std::fixed << std::setprecision(0);
		if (bytes > 1024 * 1024 * 1024) {
			s << std::fixed << std::setprecision(2);
			s << " <span class=\"transferred\">" << (double) (bytes / 1024 / 1024 / 1024) << "G</span>\r\n";
		} else if (bytes > 1024 * 1024) {
			s << std::fixed << std::setprecision(1);
			s << " <span class=\"transferred\">" << (double) (bytes / 1024 / 1024) << "M</span>\r\n";
		} else if (bytes > 1024) {
			s << " <span class=\"transferred\">" << (int) (bytes / 1024) << "K</span>\r\n";
		} else {
			s << " <span class=\"transferred\">" << (int) (bytes) << "B</span>\r\n";
		}
	}

	static void SetLogLevel (const std::string& level)
	{
		if (level == "none" || level == "error" || level == "warn" || level == "info" || level == "debug")
			i2p::log::Logger().SetLogLevel(level);
		else {
			LogPrint(eLogError, "HTTPServer: unknown loglevel set attempted");
			return;
		}
		i2p::log::Logger().Reopen ();
	}

	static void ShowPageHead (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		// Page language
		std::string currLang = i2p::context.GetLanguage ()->GetLanguage(); // get current used language
		auto it = i2p::i18n::languages.find(currLang);
		std::string langCode = it->second.ShortCode;
		// SAM
		auto sam = i2p::client::context.GetSAMBridge ();

		std::map<std::string, std::string> params;
		std::string page("");
		URL url;
		url.parse_query(params);
		page = params["page"];
		std::string token = params["token"];

		s <<
			"<!DOCTYPE html>\r\n"
			"<html lang=\"" << langCode << "\">\r\n"
			"  <head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
			"  <meta charset=\"UTF-8\">\r\n"
			"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
			"  <link rel=\"shortcut icon\" href=\"" << i2pdfavicon << "\">\r\n"
			"  <title>Purple I2P | " VERSION "</title>\r\n";
		GetStyles(s);
		s <<
			"</head>\r\n"
			"<body>\r\n"
			"<div class=\"wrapper\">\r\n<table id=\"main\">\r\n"
			"<tr><td class=\"center\" colspan=\"2\"><span class=\"header\">"
			"<a id=\"home\" href=\"" << webroot << "\">" << tr("Main page") << "</a> "
			// placeholder for graceful shutdown button (requires token)
			"<a id=\"shutdownbutton\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&amp;token=" << token <<
			"\" data-tooltip=\"" << tr("Start graceful shutdown") << "\">Shutdown</a></span></td></tr>\r\n"
			"<tr id=\"nav\"><td id=\"navlinks\" class=\"center\" colspan=\"2\">\r\n";
		if (i2p::context.IsFloodfill ())
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LEASESETS << "\">" << tr("LeaseSets") << "</a>\r\n";
		s <<
			"<a title=\"" << tr("Local destinations currently active") << "\" href=\"" << webroot << "?page="
			<< HTTP_PAGE_LOCAL_DESTINATIONS << "\">" << tr("Destinations") << "</a>\r\n"
//			"<a title=\"" << tr("Local Service Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_I2P_TUNNELS << "\">" << tr("Services") << "</a>\r\n"
//			"<a title=\"" << tr("Active Transit Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">" << tr("Transit") << "</a>\r\n"
			"<a title=\"" << tr("Router Transports and associated connections") << "\" href=\"" << webroot <<
			"?page=" << HTTP_PAGE_TRANSPORTS << "\">" << tr ("Transports") << "</a>\r\n"
			"<a title=\"" << tr("All active tunnels") << "\" href=\"" << webroot << "?page="
			<< HTTP_PAGE_TUNNELS << "\">" << tr("Tunnels") << "</a>\r\n";
		if (sam && sam->GetSessions ().size ()) {
			s << "<a title=\"" << tr("Current SAM sessions") << "\" href=\"" << webroot << "?page="
			  << HTTP_PAGE_SAM_SESSIONS << "\">" << tr("SAM Sessions") << "</a>\r\n";
		}
		s << "<a title=\"" << tr("Router control and temporary configuration") << "\" href=\"" << webroot
		  << "?page=" << HTTP_PAGE_COMMANDS << "\">" << tr("Control") << "</a>\r\n</td></tr>\r\n";
	}

	static void ShowPageTail (std::stringstream& s)
	{
		s <<
			"</table>\r\n"
			"</div>\r\n"
			"</body>\r\n"
			"</html>\r\n";
	}

	static void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<tr><td class=\"center error\" colspan=\"2\"><span id=\"warning\"></span>\r\n<b>" << tr("ERROR")
		  << ":</b>&nbsp;" << string << "</td></tr>\r\n";
	}

	static void ShowNetworkStatus (std::stringstream& s, RouterStatus status)
	{
		switch (status)
		{
			case eRouterStatusOK: s << tr("OK"); break;
			case eRouterStatusTesting: s << tr("Testing"); break;
			case eRouterStatusFirewalled: s << tr("Firewalled"); break;
			case eRouterStatusUnknown: s << tr("Unknown"); break;
			case eRouterStatusProxy: s << tr("Proxy"); break;
			case eRouterStatusMesh: s << tr("Mesh"); break;
			case eRouterStatusError:
			{
				s << tr("Error");
				switch (i2p::context.GetError ())
				{
					case eRouterErrorClockSkew:
						s << " - " << tr("Clock skew");
					break;
					case eRouterErrorOffline:
						s << " - " << tr("Offline");
					break;
					case eRouterErrorSymmetricNAT:
						s << " - " << tr("Symmetric NAT");
					break;
					default: ;
				}
				break;
			}
			default: s << tr("Unknown");
		}
	}

	void ShowStatus (std::stringstream& s, bool includeHiddenContent, i2p::http::OutputFormatEnum outputFormat)
	{
		s << "<tr id=\"version\"><td>" << tr("Version") << "</td><td>" VERSION "</td></tr>\r\n";
		s << "<tr><td>" << tr("Uptime") << "</td><td>";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "</td></tr>\r\n";
		if (i2p::context.SupportsV4 ())
		{
			s << "<tr><td>" << tr("Network Status") << "</td><td>";
			ShowNetworkStatus (s, i2p::context.GetStatus ());
			s << "<br>\r\n";
		}
		if (i2p::context.SupportsV6 ())
		{
			s << "<tr><td>" << tr("Network Status (IPv6)") << "</td><td>";
			ShowNetworkStatus (s, i2p::context.GetStatusV6 ());
			s << "<br>\r\n";
		}
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (auto remains = Daemon.gracefulShutdownInterval) {
			s << "<tr><td>" << tr("Stopping in") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#elif defined(WIN32_APP)
		if (i2p::win32::g_GracefulShutdownEndtime != 0) {
			uint16_t remains = (i2p::win32::g_GracefulShutdownEndtime - GetTickCount()) / 1000;
			s << "<tr><td>" << tr("Stopping in") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#endif
		s << "<tr><td>" << tr("Bandwidth") << "</td><td><span class=\"router recvd\">";
		s << std::fixed << std::setprecision(0);
//		s << (double) i2p::transport::transports.GetInBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "KiB/s");
		if (i2p::transport::transports.GetInBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetInBandwidth () < 1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetInBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetInBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span> <span class=\"hide\">/</span> <span class=\"router sent\">";
//		s << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "KiB/s");
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetOutBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetOutBandwidth () < 1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetOutBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span></td></tr>\r\n";
		s << "<tr><td>" << tr("Transferred") << "</td><td><span class=\"router recvd\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetTotalReceivedBytes () > 1024*1024*1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetTotalReceivedBytes () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		ShowTraffic (s, i2p::transport::transports.GetTotalReceivedBytes ());
		s << "</span> <span class=\"hide\">/</span> <span class=\"router sent\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetTotalSentBytes () > 1024*1024*1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetTotalSentBytes () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		ShowTraffic (s, i2p::transport::transports.GetTotalSentBytes ());
		s << "</span></td</tr>\r\n";
		if (i2p::context.AcceptsTunnels () && i2p::tunnel::tunnels.CountTransitTunnels()) {
			s << "<tr><td>" << tr("Transit") << "</td><td><span class=\"transit sent\">";
			s << std::fixed << std::setprecision(0);
			if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024*1024)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			ShowTraffic (s, i2p::transport::transports.GetTotalTransitTransmittedBytes ());
			s << std::fixed << std::setprecision(0);
			if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024*1024 ||
				i2p::transport::transports.GetTransitBandwidth () < 1024)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			s << " (" << (double) i2p::transport::transports.GetTransitBandwidth () / 1024;
//			s << "&#8239;" << tr(/* tr: Kibibit/s */ "KiB/s") << ")</span></td></tr>\r\n";
			s << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s") << ")</span></td></tr>\r\n";
		}
		s << "<tr><td>" << tr("Build Success") << "</td><td>";
		s << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%</td></tr>\r\n";
// TODO: Move to separate routerinfo page
/*
		s << "<tr><td>" << tr("Router Caps") << "</td><td>" << i2p::context.GetRouterInfo().GetProperty("caps") << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Data path") << "</td><td><span class=\"sensitive\">" << i2p::fs::GetUTF8DataDir() << "</span></td></tr>\r\n";
		s << "<tr><td>" << tr("Router Ident") << "</td><td><span class=\"sensitive\" hidden>" << i2p::context.GetRouterInfo().GetIdentHashBase64() << "</span></td></tr>\r\n";
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<tr><td>"<< tr("Family") << "</td><td>" << family << "<br>\r\n";
		if (!i2p::context.GetRouterInfo().GetProperty("family").empty())
			s << "<tr><td>" << tr("Router Family") << "</td><td><span class=\"sensitive\" hidden>" << i2p::context.GetRouterInfo().GetProperty("family") << "</span></td></tr>\r\n";
		for (const auto& address : i2p::context.GetRouterInfo().GetAddresses())
		{
			s << "<tr>\r\n";
			if (address->IsNTCP2 () && !address->IsPublishedNTCP2 ())
			{
				s << "<td>NTCP2";
				if (address->host.is_v6 ()) s << "v6";
				s << "</td><td><span class=\"enabled\">" << tr("supported") << "</span></td>\r\n</tr>\r\n";
				continue;
			}
			switch (address->transportStyle)
			{
				case i2p::data::RouterInfo::eTransportNTCP:
				{
					s << "<td>NTCP";
					if (address->IsPublishedNTCP2 ()) s << "2";
					if (address->host.is_v6 ()) s << "v6";
					s << "</td>\r\n";
					break;
				}
				case i2p::data::RouterInfo::eTransportSSU:
				{
					s << "<td>SSU";
					if (address->host.is_v6 ())
						s << "v6";
					s << "</td>\r\n";
					break;
				}
				default:
					s << "<td>" << tr("Unknown") << "</td>\r\n";
			}
			s << "<td><span class=\"sensitive\" hidden>" << address->host.to_string() << ":" << address->port << "</span></td>\r\n</tr>\r\n";
		}
*/
		s << "<tr><td>" << tr("Routers") << "</td><td>" << i2p::data::netdb.GetNumRouters () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Floodfills") << "</td><td>" << i2p::data::netdb.GetNumFloodfills () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("LeaseSets") << "</td><td>" << i2p::data::netdb.GetNumLeaseSets () << "</td></tr>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		s << "<tr><td>" << tr("Service Tunnels") << "</td><td><a class=\"view\" href=\"";
		s << webroot << "?page=" << HTTP_PAGE_I2P_TUNNELS << "\">" << std::to_string(clientTunnelCount) << "</a></td></tr>\r\n";
		if (i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels()) {
			s << "<tr><td>" << tr("Transit Tunnels") << "</td><td><a class=\"view\" href=\"";
			s << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">" << std::to_string(i2p::tunnel::tunnels.CountTransitTunnels()) << "</a></td></tr>\r\n";
		}

		if(outputFormat==OutputFormatEnum::forWebConsole) {
			bool httpproxy  = i2p::client::context.GetHttpProxy ()         ? true : false;
			bool socksproxy = i2p::client::context.GetSocksProxy ()        ? true : false;
			bool bob        = i2p::client::context.GetBOBCommandChannel () ? true : false;
			bool sam        = i2p::client::context.GetSAMBridge ()         ? true : false;
			bool i2cp       = i2p::client::context.GetI2CPServer ()        ? true : false;
			bool i2pcontrol;  i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
			if (httpproxy || socksproxy || bob || sam || i2cp || i2pcontrol) {
				s << "<tr><th colspan=\"2\">" << tr("Active Router Services") << "</th></tr>\r\n";
				s << "<tr><td id=\"routerservices\" class=\"center\" colspan=\"2\">";
				if (httpproxy)
					s << " <span class=\"routerservice\">HTTP " << tr("Proxy") << "</span> ";
				if (socksproxy)
					s << " <span class=\"routerservice\">SOCKS " << tr("Proxy") << "</span> ";
				if (bob)
					s << " <span class=\"routerservice\">BOB</span> ";
				if (sam)
					s << " <span class=\"routerservice\">SAM</span> ";
				if (i2cp)
					s << " <span class=\"routerservice\">I2CP</span> ";
				if (i2pcontrol)
					s << " <span class=\"routerservice\">I2PControl</span> ";
				s << "</tr></td>";
			}
/*
				s << "<tr><td>" << "HTTP " << tr("Proxy")  << "</td><td class='" << (httpproxy  ? "enabled" : "disabled") << "\">" << (httpproxy  ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
				s << "<tr><td>" << "SOCKS " << tr("Proxy") << "</td><td class='" << (socksproxy ? "enabled" : "disabled") << "\">" << (socksproxy ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
				s << "<tr><td>" << "BOB"                   << "</td><td class='" << (bob        ? "enabled" : "disabled") << "\">" << (bob        ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
				s << "<tr><td>" << "SAM"                   << "</td><td class='" << (sam        ? "enabled" : "disabled") << "\">" << (sam        ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
				s << "<tr><td>" << "I2CP"                  << "</td><td class='" << (i2cp       ? "enabled" : "disabled") << "\">" << (i2cp       ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
				s << "<tr><td>" << "I2PControl"            << "</td><td class='" << (i2pcontrol ? "enabled" : "disabled") << "\">" << (i2pcontrol ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
*/
		}

			s << "</tbody>\r\n</table>\r\n</div>\r\n";
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Local Destinations") << "</span></th></tr>\r\n<tr><td class=\"center nopadding\" colspan=\"2\"><div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n" << std::endl;
		}
		s << "</td></tr>\r\n";

		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer && !(i2cpServer->GetSessions ().empty ()))
		{
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>I2CP "<< tr("Local Destinations") << "</span></th></tr>\r\n<tr><td class=\"center nopadding i2cp\" colspan=\"2\"><div class=\"list\">\r\n";
			for (auto& it: i2cpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					auto& name = dest->GetNickname ();
					s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_I2CP_LOCAL_DESTINATION << "&i2cp_id=" << it.first << "\">[ ";
					s << name << " ]</a> <span class=\"arrowleftright\">&#8660;</span> <span class=\"b32\">" << i2p::client::context.GetAddressBook ().ToAddress(ident) <<"</span></div>\r\n" << std::endl;
				}
			}
			s << "</td></tr>\r\n";
		}
	}

	static void ShowLeaseSetDestination (std::stringstream& s, std::shared_ptr<const i2p::client::LeaseSetDestination> dest, uint32_t token)
	{
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_b64\" />\r\n"
		  << "<label for=\"slide_b64\">" << tr("Base64 Address") << "</label>\r\n";
		s << "<div class=\"slidecontent\">\r\n<div id=\"b64\">";
		s << dest->GetIdentity ()->ToBase64 () << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		if (dest->IsEncryptedLeaseSet ())
		{
			i2p::data::BlindedPublicKey blinded (dest->GetIdentity (), dest->IsPerClientAuth ());
			s << "<tr><th colspan=\"2\">" << tr("Encrypted B33 Address") << "</td</th>\r\n";
			s << "<tr><td colspan=\"2\">" << blinded.ToB33 () << ".b32.i2p</td></tr>\r\n";
		}

		if(dest->IsPublic())
		{
			std::string webroot; i2p::config::GetOption("http.webroot", webroot);
			auto base32 = dest->GetIdentHash ().ToBase32 ();
			s << "<tr><th class=\"left\" colspan=\"2\">" << tr("Address Registration String") << "</th></tr>\r\n"
				 "<tr><td colspan=\"2\"><form class=\"register\" method=\"get\" action=\"" << webroot << "\">\r\n"
				 "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_GET_REG_STRING << "\">\r\n"
				 "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n"
				 "  <input type=\"hidden\" name=\"b32\" value=\"" << base32 << "\">\r\n"
				 "  <input type=\"text\" maxlength=\"67\" name=\"name\" placeholder=\"domain.i2p\" required>\r\n"
				 "  <button type=\"submit\">" << tr("Generate") << "</button>\r\n"
				 "</form>\r\n<div class=\"note\">";
			  s << tr("<b>Note:</b> Result string can be used only for registering 2LD domains (example.i2p).")
			    << " " << tr("For registering subdomains, please use i2pd-tools.");
			  s << "</div>\r\n</td></tr>\r\n";
		}

		if(dest->GetNumRemoteLeaseSets())
		{
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_leasesets\" />\r\n"
			  << "<label for=\"slide_leasesets\">" << tr("LeaseSets")
			  << " <span class=\"hide\">[</span><span class=\"count\">" << dest->GetNumRemoteLeaseSets ()
			  << "</span><span class=\"hide\">]</span></label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<table>\r\n<thead>\r\n<tr>"
			  << "<th class=\"left\">" << tr("Address") << "</th>"
			  << "<th class=\"thin\">" << tr("Type") << "</th>"
			  << "<th class=\"thin\">" << tr("EncType") << "</th>"
			  << "</thead>\r\n<tbody class=\"tableitem\">\r\n";
			for(auto& it: dest->GetLeaseSets ())
				s << "<tr><td class=\"left\"><span class=\"b32\">" << it.first.ToBase32 () << "</span></td>\r\n"
				  << "<td class=\"center thin\">" << (int)it.second->GetStoreType () << "</td>"
				  << "<td class=\"center thin\">" << (int)it.second->GetEncryptionType () <<"</td>"
				  << "</tr>\r\n";
			s << "</tbody>\r\n</table>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		} else
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets currently active") << "</th><tr>\r\n";

		auto pool = dest->GetTunnelPool ();
		if (pool)
		{
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels\" />\r\n"
			  << "<label for=\"slide_tunnels\">" << tr("Tunnels") << "</label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
			for (auto & it : pool->GetInboundTunnels ()) { // inbound tunnels
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span>";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span>";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span>";
				}
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
			for (auto & it : pool->GetOutboundTunnels ()) { // outbound tunnels
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span>";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span>";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span>";
				}
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumSentBytes ());
				s << "</span></div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";

		if (dest->GetNumIncomingTags () > 0) {
			s << "<tr><th colspan=\"2\">" << tr("Incoming Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"count\">"
			  << dest->GetNumIncomingTags () << "</span><span class=\"hide\">]</span></th></tr>\r\n";
		} else {
			s << "<tr><th colspan=\"2\">" << tr("No Incoming Session Tags") << "</th></tr>\r\n";
		}
		if (!dest->GetSessions ().empty ()) {
			std::stringstream tmp_s; uint32_t out_tags = 0;
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">";
			for (const auto& it: dest->GetSessions ()) {
				tmp_s << "<tr><td class=\"left\">" << i2p::client::context.GetAddressBook ().ToAddress(it.first)
					  << "</td><td class=\"center thin\">" << it.second->GetNumOutgoingTags () << "</td></tr>\r\n";
				out_tags += it.second->GetNumOutgoingTags ();
			}
			s << "<tr><th colspan=\"2\">" << tr("Outgoing Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"count\">" << out_tags
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n"
			  << "<tr><td class=\"center nopadding\" colspan=\"2\"><table>\r\n"
			  << "<thead>\r\n<tr><th class=\"left\">" << tr("Destination") << "</th><th class=\"thin\">" << tr("Count")
			  << "</th></thead>\r\n<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</td></tr>\r\n";
		} else
			s << "<tr><th colspan=\"2\">" << tr("No Outgoing Session Tags") << "</th></tr>\r\n";

		auto numECIESx25519Tags = dest->GetNumIncomingECIESx25519Tags ();
		if (numECIESx25519Tags > 0) {
			s << "<tr><th colspan=\"2\">ECIESx25519<br>\r\n" << tr("Incoming Tags")
			  << " <span class=\"hide\">[</span><span class=\"count\">" << numECIESx25519Tags
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";
			if (!dest->GetECIESx25519Sessions ().empty ())
			{
				std::stringstream tmp_s; uint32_t ecies_sessions = 0;
				for (const auto& it: dest->GetECIESx25519Sessions ()) {
					tmp_s << "<tr><td class=\"left\">"
					      << i2p::client::context.GetAddressBook ().ToAddress(it.second->GetDestination ())
					      << "</td><td class=\"center thin\">" << it.second->GetState () << "</td></tr>\r\n";
					ecies_sessions++;
				}
				s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n"
				  << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide-ecies-sessions\" />\r\n"
				  << "<label for=\"slide-ecies-sessions\">" << tr("Tag Sessions")
				  << " <span class=\"hide\">[</span><span class=\"count\">" << ecies_sessions
				  << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent\">\r\n<table>\r\n<thead><th class=\"left\">" << tr("Destination") << "</th><th>"
				  << tr("Status") << "</th></thead>\r\n<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</div>\r\n</div>\r\n";
			} else
				s << "<tr><th coslpan=\"2\">" << tr("No Tag Sessions") << "</th></tr>\r\n";
		}
	}

	void ShowLocalDestination (std::stringstream& s, const std::string& b32, uint32_t token)
	{
		i2p::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = i2p::client::context.FindLocalDestination (ident);
		if (dest) {
			std::string b32Short = b32.substr(0,6);
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Local Destination") << " [" << b32Short << "]</span></th></tr>\r\n";
		} else
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Local Destination") << " [" << tr("Not Found") << "]</span></th></tr>\r\n";

		if (dest)
		{
			ShowLeaseSetDestination (s, dest, token);
			// Print table with streams information
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide-streams\" />\r\n"
			  << "<label for=\"slide-streams\">" << tr("Streams") << "</label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<table>\r\n<thead>\r\n<tr>";
			s << "<th class=\"streamid\">ID</th>";
			s << "<th class=\"streamdest\">Destination</th>";
			s << "<th>TX</th>";
			s << "<th>RX</th>";
			s << "<th>Out</th>";
			s << "<th>In</th>";
			s << "<th>Buf</th>";
			s << "<th>RTT</th>";
			s << "<th>Win</th>";
			s << "<th>Status</th>";
			s << "</tr>\r\n</thead>\r\n";
			s << "<tbody class=\"tableitem\">\r\n";

			for (const auto& it: dest->GetAllStreams ())
			{
				auto streamDest = i2p::client::context.GetAddressBook ().ToAddress(it->GetRemoteIdentity ());
				std::string streamDestShort = streamDest.substr(0,10) + "&hellip;b32.i2p";
				s << "<tr>";
				s << "<td class=\"center nopadding streamid\">"
				  << "<a class=\"button\" href=\"/?cmd=" << HTTP_COMMAND_KILLSTREAM << "&b32=" << b32 << "&streamID="
				  << it->GetRecvStreamID () << "&token=" << token << "\" title=\"" << tr("Close stream")
				  << "\"><span class=\"close\">&#10005;</span> " << it->GetRecvStreamID () << "</a></td>";
				s << "<td class=\"streamdest\" title=\"" << streamDest << "\">" << streamDestShort << "</td>";
				s << std::fixed << std::setprecision(0);
				if (it->GetNumSentBytes () > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumSentBytes ()  / 1024 / 1024 / 1024 << "G</td>";
				} else if (it->GetNumSentBytes () > 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumSentBytes ()  / 1024 / 1024 << "M</td>";
				} else {
					s << "<td>" << it->GetNumSentBytes () / 1024 << "K</td>";
				}
				if (it->GetNumReceivedBytes () > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumReceivedBytes ()  / 1024 / 1024 / 1024 << "G</td>";
				} else if (it->GetNumReceivedBytes () > 1024 * 1024) {
					s << std::fixed << std::setprecision(1);
					s << "<td>" << (double) it->GetNumReceivedBytes ()  / 1024 / 1024 << "M</td>";
				} else {
					s << "<td>" << it->GetNumReceivedBytes () / 1024 << "K</td>";
				}
				s << "<td>" << it->GetSendQueueSize () << "</td>";
				s << "<td>" << it->GetReceiveQueueSize () << "</td>";
				s << "<td>" << it->GetSendBufferSize () << "</td>";
				s << "<td>" << it->GetRTT () << "</td>";
				s << "<td>" << it->GetWindowSize () << "</td>";
				s << "<td class=\"center\">" << (int) it->GetStatus () << "</td>";
				s << "</tr>\r\n";
			}
			s << "</tbody>\r\n</table>\r\n</div>\r\n</div>\r\n</td></tr>";
		}
	}

	void ShowI2CPLocalDestination (std::stringstream& s, const std::string& id)
	{
		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer)
		{
			s << "<b>I2CP " << tr("Local Destination") << ":</b><br>\r\n<br>\r\n";
			auto it = i2cpServer->GetSessions ().find (std::stoi (id));
			if (it != i2cpServer->GetSessions ().end ())
				ShowLeaseSetDestination (s, it->second->GetDestination (), 0);
			else
				ShowError(s, tr("I2CP session not found"));
		}
		else
			ShowError(s, tr("I2CP is not enabled"));
	}

	void ShowLeasesSets(std::stringstream& s)
	{
		if (i2p::data::netdb.GetNumLeaseSets ())
		{
			s << "<tr><th class=\"nopadding\" colspan=\"2\">" << tr("LeaseSets") << "</th><tr>\r\n<tr><td class=\"center nopadding\"><div class=\"list\">\r\n";
			int counter = 1;
			// for each lease set
			i2p::data::netdb.VisitLeaseSets(
				[&s, &counter](const i2p::data::IdentHash dest, std::shared_ptr<i2p::data::LeaseSet> leaseSet)
				{
					// create copy of lease set so we extract leases
					auto storeType = leaseSet->GetStoreType ();
					std::unique_ptr<i2p::data::LeaseSet> ls;
					if (storeType == i2p::data::NETDB_STORE_TYPE_LEASESET)
						ls.reset (new i2p::data::LeaseSet (leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
					else
						ls.reset (new i2p::data::LeaseSet2 (storeType, leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
					if (!ls) return;
					s << "<div class=\"leaseset listitem";
					if (ls->IsExpired())
						s << " expired"; // additional css class for expired
					s << "\">\r\n";
					if (!ls->IsValid())
						s << "<div class=\"invalid\">!! " << tr("Invalid") << " !! </div>\r\n";
					s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide" << (counter++) << "\" />\r\n"
					  << "<label for=\"slide" << counter << "\">" << dest.ToBase32() << "</label>\r\n";
					s << "<div class=\"slidecontent\">\r\n";
					s << "<b>" << tr("Store type") << ":</b> " << (int)storeType << "<br>\r\n";
					s << "<b>" << tr("Expires") << ":</b> " << ConvertTime(ls->GetExpirationTime()) << "<br>\r\n";
					if (storeType == i2p::data::NETDB_STORE_TYPE_LEASESET || storeType == i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2)
					{
						// leases information is available
						auto leases = ls->GetNonExpiredLeases();
						s << "<b>" << tr("Non Expired Leases") << ": " << leases.size() << "</b><br>\r\n";
						for ( auto & l : leases )
						{
							s << "<b>" << tr("Gateway") << ":</b> " << l->tunnelGateway.ToBase64() << "<br>\r\n";
							s << "<b>" << tr("TunnelID") << ":</b> " << l->tunnelID << "<br>\r\n";
							s << "<b>" << tr("EndDate") << ":</b> " << ConvertTime(l->endDate) << "<br>\r\n";
						}
					}
					s << "</div>\r\n</div>\r\n</div>\r\n";
				}
			);
			s << "</td></tr>\r\n";
			// end for each lease set
		}
		else if (!i2p::context.IsFloodfill ())
		{
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets") << " (" << tr("not floodfill") << ")</th</tr>\r\n";
		}
		else
		{
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets") << "</th</tr>\r\n";
		}
	}

	void ShowTunnels (std::stringstream& s)
	{
		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Tunnels") << "</span></th><tr>\r\n";
		s << "<tr><th colspan=\"2\">" << tr("Queue size") << ": " << i2p::tunnel::tunnels.GetQueueSize () << "</th></tr>\r\n";

		auto ExplPool = i2p::tunnel::tunnels.GetExploratoryPool ();

		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels_client\" />\r\n"
		  << "<label for=\"slide_tunnels_client\">" << tr("Client Tunnels") << "</label>\r\n"; // TODO: separate client & exploratory tunnels into sections
		s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			s << "<div class=\"listitem in\">"
			  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
			  << "<span class=\"chain inbound\">";
			it->Print(s);
			if(it->LatencyIsKnown()) {
				s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
				if (it->GetMeanLatency() >= 1000) {
					s << std::fixed << std::setprecision(2);
					s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span>";
				} else {
					s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span>";
				}
			} else { // placeholder for alignment
				s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span>";
			}
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
			s << "</span></div>\r\n";
		}
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			s << "<div class=\"listitem out\">"
			  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
			  << "<span class=\"chain outbound\">";
			it->Print(s);
			if(it->LatencyIsKnown())
				s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">" << it->GetMeanLatency() << tr("ms") << "</span>";
			else // placeholder for alignment
				s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span>";
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
			s << "</span>\r\n</div>\r\n";
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Router Commands") << "</span></th></tr><tr><td class=\"center\" colspan=\"2\">\r\n";
		s << "  <a id=\"homelink\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token << "\">" << tr("Run peer test") << "</a><br>\r\n";

		// s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << "\">Reload config</a><br>\r\n";

		if (i2p::context.AcceptsTunnels ())
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token << "\">" << tr("Decline transit tunnels") << "</a><br>\r\n";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token << "\">" << tr("Accept transit tunnels") << "</a><br>\r\n";

		if (i2p::tunnel::tunnels.CountTransitTunnels()) {
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			if (Daemon.gracefulShutdownInterval)
				s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">" << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">" << tr("Start graceful shutdown") << "</a><br>\r\n";
#elif defined(WIN32_APP)
			if (i2p::util::DaemonWin32::Instance().isGraceful)
				s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">" << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">" << tr("Start graceful shutdown") << "</a><br>\r\n";
#endif
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token << "\">" << tr("Force shutdown") << "</a></td></tr>\r\n";
		} else {
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token << "\">" << tr("Shutdown") << "</a></td></tr>\r\n";
		}
		s << "<tr><td class=\"center\" colspan=\"2\"><a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RELOAD_CSS << "&token=" << token << "\">"
		  << tr("Reload external CSS styles") << "</a>\r\n</td></tr>";

		s << "<tr><td class=\"center\" colspan=\"2\">\r\n<div class=\"note\">" << tr("<b>Note:</b> Configuration changes made here persist for the duration of the router session and will not be saved to your config file.") << "</div>\r\n</td></tr>";

		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Logging Level") << "</span></th></tr>\r\n<tr><td class=\"center\" colspan=\"2\">";
		s << "  <a class=\"button\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=none&token=" << token << "\"> none </a> \r\n";
		s << "  <a class=\"button\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=error&token=" << token << "\"> error </a> \r\n";
		s << "  <a class=\"button\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=warn&token=" << token << "\"> warn </a> \r\n";
		s << "  <a class=\"button\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=info&token=" << token << "\"> info </a> \r\n";
		s << "  <a class=\"button\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=debug&token=" << token << "\"> debug </a></td></tr>\r\n";

		if (i2p::context.AcceptsTunnels ()) {
			uint16_t maxTunnels = GetMaxNumTransitTunnels ();
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Maximum Transit Tunnels") << "</span></th></tr>\r\n<tr><td class=\"center\" colspan=\"2\">\r\n";
			s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_LIMITTRANSIT << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
			s << "  <input type=\"number\" min=\"0\" max=\"65535\" name=\"limit\" value=\"" << maxTunnels << "\">\r\n";
			s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
			s << "</form>\r\n</td></tr>\r\n";
		}

		std::string currLang = i2p::context.GetLanguage ()->GetLanguage(); // get current used language
		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Console Display Language") << "</span></th></tr>\r\n<tr><td class=\"center\" colspan=\"2\">\r\n";
		s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_SETLANGUAGE << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
		s << "  <select name=\"lang\" id=\"lang\">\r\n";
		for (const auto& it: i2p::i18n::languages)
			s << "    <option value=\"" << it.first << "\"" << ((it.first.compare(currLang) == 0) ? " selected" : "") << ">" << it.second.LocaleName << "</option>\r\n";
		s << "  </select>\r\n";
		s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
		s << "</form>\r\n</td></tr>\r\n";

	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		if(i2p::tunnel::tunnels.CountTransitTunnels())
		{
			s << "<tr><th colspan=\"2\">" << tr("Transit Tunnels") << "</th></tr><tr><td class=\"center nopadding\" colspan=\"2\">\r\n<div class=\"list\">\r\n";
			for (const auto& it: i2p::tunnel::tunnels.GetTransitTunnels ())
			{
				s << "<div class=\"listitem\"><span class=\"chain transit\">";
				if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
					s << it->GetTunnelID () << " <span class=\"arrowright\">&#8658;</span> ";
				else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
					s << "<span class=\"arrowright\">&#8658;</span> " << "<span class=\"tunnelid\">" << it->GetTunnelID () << "</span>";
				else
					s << "<span class=\"arrowright\">&#8658;</span> <span class=\"tunnelid\">" << it->GetTunnelID ()
					  << "</span> <span class=\"arrowright\">&#8658;</span> ";
				s << " <span class=\"sent\">" << it->GetNumTransmittedBytes () << "B</span></div>\r\n";
			}
			s << "</span></div></td></tr>\r\n";
		}
		else
		{
			s << "<tr><th colspan=\"2\">" << tr("No active transit tunnels") << "</th></tr>\r\n";
		}
	}

	template<typename Sessions>
	static void ShowNTCPTransports (std::stringstream& s, const Sessions& sessions, const std::string name)
	{
		std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
		for (const auto& it: sessions )
		{
			if (it.second && it.second->IsEstablished () && !it.second->GetRemoteEndpoint ().address ().is_v6 ())
			{
				tmp_s << "<div class=\"listitem\">";
				if (it.second->IsOutgoing ())
					tmp_s << "<span class=\"arrowup\">&#8657;</span>";
				else
					tmp_s << "<span class=\"arrowdown\">&#8659;</span>";
				tmp_s << " <span class=\"chain\">";
				tmp_s << "<span class=\"hop\">" << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << "</span>"
					  << " <a target=\"_blank\" href=\"https://gwhois.org/"
					  << it.second->GetRemoteEndpoint ().address ().to_string () << "\" data-tooltip=\""
					  << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					  << it.second->GetRemoteEndpoint ().address ().to_string () << "</span></a>";
				tmp_s << std::fixed << std::setprecision(0);
				if (it.second->GetNumSentBytes () > 1024 * 1024) {
					tmp_s << std::fixed << std::setprecision(1);
					tmp_s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
				}
				tmp_s << std::fixed << std::setprecision(0);
				if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
					tmp_s << std::fixed << std::setprecision(1);
					tmp_s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
				}
				tmp_s << "</span></div>\r\n" << std::endl;
				cnt++;
			}
			if (it.second && it.second->IsEstablished () && it.second->GetRemoteEndpoint ().address ().is_v6 ())
			{
				tmp_s6 << "<div class=\"listitem\">";
				if (it.second->IsOutgoing ())
					tmp_s6 << "<span class=\"arrowup\">&#8657;</span>";
				else
					tmp_s6 << "<span class=\"arrowdown\">&#8659;</span>";
				tmp_s6 << " <span class=\"chain\">";
				tmp_s6 << "<span class=\"hop\">" << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << "</span>"
					   << " <a target=\"_blank\" href=\"https://gwhois.org/"
					   << it.second->GetRemoteEndpoint ().address ().to_string () << "\" data-tooltip=\""
					   << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					   << it.second->GetRemoteEndpoint ().address ().to_string () << "</span></a>";
				tmp_s6 << std::fixed << std::setprecision(0);
				if (it.second->GetNumSentBytes () > 1024 * 1024) {
					tmp_s6 << std::fixed << std::setprecision(1);
					tmp_s6 << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s6 << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
				}
				tmp_s6 << " <span class=\"hide\">/</span>";
				tmp_s6 << std::fixed << std::setprecision(0);
				if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
					tmp_s6 << std::fixed << std::setprecision(1);
					tmp_s6 << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s6 << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
				}
				tmp_s6 << "</span></div>\r\n" << std::endl;
				cnt6++;
			}
		}
		if (!tmp_s.str ().empty ())
		{
			s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_" << boost::algorithm::to_lower_copy(name)
			  << "\" />\r\n<label for=\"slide_" << boost::algorithm::to_lower_copy(name) << "\">" << name
			  << " <span class=\"hide\">[</span><span class=\"count\">" << cnt
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s.str () << "</div>\r\n</div>\r\n";
		}
		if (!tmp_s6.str ().empty ())
		{
			s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\" />\r\n"
			  << "<label for=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\">" << name
			  << "v6 <span class=\"hide\">[</span><span class=\"count\">" << cnt6
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s6.str () << "</div>\r\n</div>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Transports") << "</span></th></tr>\r\n"
		  << "<tr><td id=\"transports\" class=\"center nopadding\" colspan=\"2\">";
		auto ntcp2Server = i2p::transport::transports.GetNTCP2Server ();
		if (ntcp2Server)
		{
			auto sessions = ntcp2Server->GetNTCP2Sessions ();
			if (!sessions.empty ())
				ShowNTCPTransports (s, sessions, "NTCP2");
		}
		auto ssuServer = i2p::transport::transports.GetSSUServer ();
		if (ssuServer)
		{
			auto sessions = ssuServer->GetSessions ();
			if (!sessions.empty ())
			{
				s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_ssu\" />\r\n"
				  << "<label for=\"slide_ssu\">SSU <span class=\"hide\">[</span><span class=\"count\">"
				  << (int) sessions.size() << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent list\">\r\n";
				for (const auto& it: sessions)
				{
					s << "<div class=\"listitem SSU\">";
					if (it.second->IsOutgoing ())
						s << "<span class=\"arrowup\">&#8657;</span>";
					else
						s << "<span class=\"arrowdown\">&#8659;</span>";
					s << " <span class=\"chain\">";
					auto endpoint = it.second->GetRemoteEndpoint ();
//					s << " <span class=\"host\">" << endpoint.address ().to_string () << ":" << endpoint.port () << "</span>";
					s << " <a target=\"_blank\" href=\"https://gwhois.org/"
					  << endpoint.address ().to_string () << "\" data-tooltip=\""
					  << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					  << endpoint.address ().to_string () << ":" << endpoint.port () << "</span></a>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumSentBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
					}
					s << " <span class=\"hide\">/</span>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
					}
					if (it.second->GetRelayTag ())
						s << " <span class=\"itag\" data-tooltip=\"itag\">" << it.second->GetRelayTag () << "</span>";
					s << "</span></div>\r\n" << std::endl;
				}
				s << "</div>\r\n</div>\r\n";
			}
			auto sessions6 = ssuServer->GetSessionsV6 ();
			if (!sessions6.empty ())
			{
				s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_ssuv6\" />\r\n"
				  << "<label for=\"slide_ssuv6\">SSUv6 <span class=\"hide\">[</span><span class=\"count\">"
				  << (int) sessions6.size() << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent list\">\r\n";
				for (const auto& it: sessions6)
				{
					s << "<div class=\"listitem SSU\">";
					if (it.second->IsOutgoing ())
						s << "<span class=\"arrowup\">&#8657;</span>";
					else
						s << "<span class=\"arrowdown\">&#8659;</span>";
					s << " <span class=\"chain\">";
					auto endpoint = it.second->GetRemoteEndpoint ();
					s << " <span class=\"host\">" << endpoint.address ().to_string () << ":" << endpoint.port () << "</span>";
					s << std::fixed << std::setprecision(0);

					if (it.second->GetNumSentBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
					}
					s << " <span class=\"hide\">/</span>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
					}
					if (it.second->GetRelayTag ())
						s << " <span class=\"itag\" data-tooltip=\"itag\">" << it.second->GetRelayTag () << "</span>";
					s << "</span>\r\n</div>\r\n" << std::endl;
				}
				s << "</div>\r\n</div>\r\n</td></tr>\r\n";
			}
		}
	}

	void ShowSAMSessions (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam)
		{
			ShowError(s, tr("SAM disabled"));
			return;
		}

		if (sam->GetSessions ().size ())
		{
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("SAM sessions")
			  << "</span></th><tr>\r\n<tr><td class=\"center nopadding\">\r\n<div class=\"list\">\r\n";
			for (auto& it: sam->GetSessions ())
			{
				auto& name = it.second->GetLocalDestination ()->GetNickname ();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << "\">";
				s << name << " (" << it.first << ")</a></div>\r\n" << std::endl;
			}
			s << "</div>\r\n</td></tr>\r\n";
		}
		else
			s << "<tr><th colspan=\"2\">" << tr("No active SAM sessions") << "</th></tr>\r\n";
	}

	void ShowSAMSession (std::stringstream& s, const std::string& id)
	{
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam) {
			ShowError(s, tr("SAM disabled"));
			return;
		}

		auto session = sam->FindSession (id);
		if (!session) {
			ShowError(s, tr("SAM session not found"));
			return;
		}

		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr><th colspan=\"2\">" << tr("SAM Session") << "</th><tr>\r\n<tr><td class=\"center nopadding\">\r\n<div class=\"list\">\r\n";
		auto& ident = session->GetLocalDestination ()->GetIdentHash();
		s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
		s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n";
		s << "<br>\r\n";
		s << "<tr><th colspan=\"2\">" << tr("Streams") << "</th><tr>\r\n<div class=\"list\">\r\n";
		for (const auto& it: sam->ListSockets(id))
		{
			s << "<div class=\"listitem\">";
			switch (it->GetSocketType ())
			{
				case i2p::client::eSAMSocketTypeSession  : s << "session";  break;
				case i2p::client::eSAMSocketTypeStream   : s << "stream";   break;
				case i2p::client::eSAMSocketTypeAcceptor : s << "acceptor"; break;
				case i2p::client::eSAMSocketTypeForward  : s << "forward";  break;
				default: s << "unknown"; break;
			}
			s << " [" << it->GetSocket ().remote_endpoint() << "]";
			s << "</div>\r\n";
		}
		s << "</div></td></tr>\r\n";
	}

	void ShowI2PTunnels (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Service Tunnels") << "</span></th></tr><tr>"
		  << "<td class=\"center nopadding i2ptunnels\" colspan=\"2\">\r\n<div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n"<< std::endl;
		}
		auto httpProxy = i2p::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "HTTP " << tr("Proxy") << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n"<< std::endl;
		}
		auto socksProxy = i2p::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "SOCKS " << tr("Proxy") << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n" << std::endl;
		}
		s << "</div></td></tr>\r\n";

		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Server Tunnels") << "</span></th></tr><tr><td class=\"center nopadding i2ptunnels\" colspan=\"2\">\r\n<div class=\"list\">\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowright\">&#8658;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</span></div>\r\n" << std::endl;
			}
			s << "</div></td></tr>\r\n";
		}

		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Client Forwards") << "</span></th></tr><tr><td class=\"center nopadding i2ptunnels\" colspan=\"2\">\r\n<div class=\"list\">\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div></td></tr>\r\n";
		}
		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			s << "<tr><th class=\"sectiontitle\" colspan=\"2\"><span>" << tr("Server Forwards") << "</span></th></tr>\r\n"
			  << "<tr><td class=\"center nopadding i2ptunnels\" colspan=\"2\">\r\n<div class=\"list\">\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div></td></tr>\r\n";
		}
	}

	HTTPConnection::HTTPConnection (std::string hostname, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Socket (socket), m_BufferLen (0), expected_host(hostname)
	{
		/* cache options */
		i2p::config::GetOption("http.auth", needAuth);
		i2p::config::GetOption("http.user", user);
		i2p::config::GetOption("http.pass", pass);
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, HTTP_CONNECTION_BUFFER_SIZE),
			std::bind(&HTTPConnection::HandleReceive, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode) {
			if (ecode != boost::asio::error::operation_aborted)
				Terminate (ecode);
			return;
		}
		m_Buffer[bytes_transferred] = '\0';
		m_BufferLen = bytes_transferred;
		RunRequest();
		Receive ();
	}

	void HTTPConnection::RunRequest ()
	{
		HTTPReq request;
		int ret = request.parse(m_Buffer);
		if (ret < 0) {
			m_Buffer[0] = '\0';
			m_BufferLen = 0;
			return; /* error */
		}
		if (ret == 0)
			return; /* need more data */

		HandleRequest (request);
	}

	void HTTPConnection::Terminate (const boost::system::error_code& ecode)
	{
		if (ecode == boost::asio::error::operation_aborted)
			return;
		boost::system::error_code ignored_ec;
		m_Socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
		m_Socket->close ();
	}

	bool HTTPConnection::CheckAuth (const HTTPReq & req)
	{
		/* method #1: http://user:pass@127.0.0.1:7070/ */
		if (req.uri.find('@') != std::string::npos) {
			URL url;
			if (url.parse(req.uri) && url.user == user && url.pass == pass)
				return true;
		}
		/* method #2: 'Authorization' header sent */
		auto provided = req.GetHeader ("Authorization");
		if (provided.length () > 0)
		{
			std::string expected = "Basic " + i2p::data::ToBase64Standard (user + ":" + pass);
			if (expected == provided) return true;
		}

		LogPrint(eLogWarning, "HTTPServer: auth failure from ", m_Socket->remote_endpoint().address ());
		return false;
	}

	void HTTPConnection::HandleRequest (const HTTPReq & req)
	{
		std::stringstream s;
		std::string content;
		HTTPRes res;

		LogPrint(eLogDebug, "HTTPServer: request: ", req.uri);

		if (needAuth && !CheckAuth(req)) {
			res.code = 401;
			res.add_header("WWW-Authenticate", "Basic realm=\"WebAdmin\"");
			SendReply(res, content);
			return;
		}
		bool strictheaders;
		i2p::config::GetOption("http.strictheaders", strictheaders);
		if (strictheaders)
		{
			std::string http_hostname;
			i2p::config::GetOption("http.hostname", http_hostname);
			std::string host = req.GetHeader("Host");
			auto idx = host.find(':');
			/* strip out port so it's just host */
			if (idx != std::string::npos && idx > 0)
			{
				host = host.substr(0, idx);
			}
			if (!(host == expected_host || host == http_hostname))
			{
				/* deny request as it's from a non whitelisted hostname */
				res.code = 403;
				content = "host mismatch";
				SendReply(res, content);
				return;
			}
		}
		// HTML head start
		ShowPageHead (s);
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
			ShowStatus (s, true, i2p::http::OutputFormatEnum::forWebConsole);
			res.add_header("Refresh", "10");
		}
		ShowPageTail (s);

		res.code = 200;
		content = s.str ();
		SendReply (res, content);
	}

	std::map<uint32_t, uint32_t> HTTPConnection::m_Tokens;

	uint32_t HTTPConnection::CreateToken ()
	{
		uint32_t token;
		RAND_bytes ((uint8_t *)&token, 4);
		token &= 0x7FFFFFFF; // clear first bit
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto it = m_Tokens.begin (); it != m_Tokens.end (); )
		{
			if (ts > it->second + TOKEN_EXPIRATION_TIMEOUT)
				it = m_Tokens.erase (it);
			else
				++it;
		}
		m_Tokens[token] = ts;
		return token;
	}

	void HTTPConnection::HandlePage (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
	{
		std::map<std::string, std::string> params;
		std::string page("");
		URL url;

		url.parse(req.uri);
		url.parse_query(params);
		page = params["page"];

		if (page == HTTP_PAGE_TRANSPORTS)
			ShowTransports (s);
		else if (page == HTTP_PAGE_TUNNELS)
			ShowTunnels (s);
		else if (page == HTTP_PAGE_COMMANDS)
		{
			uint32_t token = CreateToken ();
			ShowCommands (s, token);
		}
		else if (page == HTTP_PAGE_TRANSIT_TUNNELS)
			ShowTransitTunnels (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATIONS)
			ShowLocalDestinations (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATION)
		{
			uint32_t token = CreateToken ();
			ShowLocalDestination (s, params["b32"], token);
		}
		else if (page == HTTP_PAGE_I2CP_LOCAL_DESTINATION)
			ShowI2CPLocalDestination (s, params["i2cp_id"]);
		else if (page == HTTP_PAGE_SAM_SESSIONS)
			ShowSAMSessions (s);
		else if (page == HTTP_PAGE_SAM_SESSION)
			ShowSAMSession (s, params["sam_id"]);
		else if (page == HTTP_PAGE_I2P_TUNNELS)
			ShowI2PTunnels (s);
		else if (page == HTTP_PAGE_LEASESETS)
			ShowLeasesSets(s);
		else {
			res.code = 400;
			ShowError(s, tr("Unknown page") + ": " + page);
			return;
		}
	}

	void HTTPConnection::HandleCommand (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
	{
		std::map<std::string, std::string> params;
		URL url;

		url.parse(req.uri);
		url.parse_query(params);

		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		std::string redirect = "2; url=" + webroot + "?page=commands";
		std::string token = params["token"];

		if (token.empty () || m_Tokens.find (std::stoi (token)) == m_Tokens.end ())
		{
			ShowError(s, tr("Invalid token"));
			return;
		}

		std::string cmd = params["cmd"];
		if (cmd == HTTP_COMMAND_RUN_PEER_TEST)
			i2p::transport::transports.PeerTest ();
		else if (cmd == HTTP_COMMAND_RELOAD_CONFIG)
			i2p::client::context.ReloadConfig ();
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (true);
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (false);
		else if (cmd == HTTP_COMMAND_SHUTDOWN_START)
		{
			i2p::context.SetAcceptsTunnels (false);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 10*60;
#elif defined(WIN32_APP)
			i2p::win32::GracefulShutdown ();
#endif
		}
		else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL)
		{
			i2p::context.SetAcceptsTunnels (true);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))  || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 0;
#elif defined(WIN32_APP)
			i2p::win32::StopGracefulShutdown ();
#endif
		}
		else if (cmd == HTTP_COMMAND_SHUTDOWN_NOW)
		{
#ifndef WIN32_APP
			Daemon.running = false;
#else
			i2p::win32::StopWin32App ();
#endif
		}
		else if (cmd == HTTP_COMMAND_LOGLEVEL)
		{
			std::string level = params["level"];
			SetLogLevel (level);
		}
		else if (cmd == HTTP_COMMAND_KILLSTREAM)
		{
			std::string b32 = params["b32"];
			uint32_t streamID = std::stoul(params["streamID"], nullptr);

			i2p::data::IdentHash ident;
			ident.FromBase32 (b32);
			auto dest = i2p::client::context.FindLocalDestination (ident);

			if (streamID)
			{
				if (dest)
				{
					if(dest->DeleteStream (streamID))
						s << "<tr><td class=\"notify center\" colspan=\2\"><span id=\"success\"></span><b>" << tr("SUCCESS") << "</b>:&nbsp;"
						  << tr("Stream closed") << "</td></tr>\r\n";
					else
						s << "<tr><td class=\"notify error center\" colspan=\2\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Stream not found or already was closed") << "</td></tr>\r\n";
				}
				else
					s << "<tr><td class=\"notify error center\" colspan=\2\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Destination not found") << "</td></tr>\r\n";
			}
			else
				s << "<tr><td class=\"notify error center\" colspan=\2\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
				  << tr("StreamID can't be null") << "</td></tr>\r\n";

			redirect = "2; url=" + webroot + "?page=local_destination&b32=" + b32;
			res.add_header("Refresh", redirect.c_str());
			return;
		}
		else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
		{
			uint32_t limit = std::stoul(params["limit"], nullptr);
			if (limit > 0 && limit <= 65535)
				SetMaxNumTransitTunnels (limit);
			else {
				s << "<tr><td class=\"notify error center\" colspan=\2\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
				  << tr("Transit tunnels count must not exceed 65535") << "\r\n</td></tr>\r\n";
				res.add_header("Refresh", redirect.c_str());
				return;
			}
		}
		else if (cmd == HTTP_COMMAND_GET_REG_STRING)
		{
			std::string b32 = params["b32"];
			std::string name = i2p::http::UrlDecode(params["name"]);

			i2p::data::IdentHash ident;
			ident.FromBase32 (b32);
			auto dest = i2p::client::context.FindLocalDestination (ident);

			if (dest)
			{
				std::size_t pos;
				pos = name.find (".i2p");
				if (pos == (name.length () - 4))
				{
					pos = name.find (".b32.i2p");
					if (pos == std::string::npos)
					{
						auto signatureLen = dest->GetIdentity ()->GetSignatureLen ();
						uint8_t * signature = new uint8_t[signatureLen];
						char * sig = new char[signatureLen*2];
						std::stringstream out;

						out << name << "=" << dest->GetIdentity ()->ToBase64 ();
						dest->Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
						auto len = i2p::data::ByteStreamToBase64 (signature, signatureLen, sig, signatureLen*2);
						sig[len] = 0;
						out << "#!sig=" << sig;
						s << "<tr><td class=\"notify center\" colspan=\"2\"><span id=\"success\"></span><b>" << tr("SUCCESS")
						  << "</b>:<br>\r\n<form action=\"http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/add\""
						  << " method=\"post\" rel=\"noreferrer\" target=\"_blank\">\r\n"
						  << "<textarea readonly name=\"record\" cols=\"80\" rows=\"10\">" << out.str () << "</textarea>\r\n<br>\r\n<br>\r\n"
						  << "<b>" << tr("Register at reg.i2p") << ":</b>\r\n<br>\r\n"
						  << "<b>" << tr("Description") << ":</b>\r\n<input type=\"text\" maxlength=\"64\" name=\"desc\" placeholder=\""
						  << tr("Short description of domain") << "\">\r\n"
						  << "<input type=\"submit\" value=\"" << tr("Submit") << "\">\r\n"
						  << "</form>\r\n</td></tr>\r\n";
						delete[] signature;
						delete[] sig;
					}
					else
						s << "<tr><td class=\"notify error center\" colspan=\"2\">" << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Domain can't end with .b32.i2p") << "\r\n<br>\r\n</td></tr>\r\n";
				}
				else
					s << "<tr><td class=\"notify error center\" colspan=\"2\">" << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Domain must end with .i2p") << "\r\n<br>\r\n</td></tr>\r\n";
			}
			else
				s << "<tr><td class=\"notify error center\" colspan=\"2\">" << tr("ERROR") << "</b>:&nbsp;"
				  << tr("No such destination found") << "\r\n<br>\r\n<</td></tr>\r\n";

//			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a>\r\n";
			return;
		}
		else if (cmd == HTTP_COMMAND_SETLANGUAGE)
		{
			std::string lang = params["lang"];
			std::string currLang = i2p::context.GetLanguage ()->GetLanguage();

			if (currLang.compare(lang) != 0)
				i2p::i18n::SetLanguage(lang);
		}
		else if (cmd == HTTP_COMMAND_RELOAD_CSS)
		{
			LoadExtCSS();
		}
		else
		{
			res.code = 400;
			ShowError(s, tr("Unknown command") + ": " + cmd);
			return;
		}

		s << "<tr><td class=\"notify center\" colspan=\"2\"><span id=\"success\"></span>";
		if (cmd == HTTP_COMMAND_SHUTDOWN_NOW)
			s << tr("Immediate router shutdown initiated");
		else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL)
			s << tr("Router shutdown cancelled");
		else if (cmd == HTTP_COMMAND_RELOAD_CSS)
			s << tr("Console CSS stylesheet reloaded");
		else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
			s << tr("Maximum transit tunnels configured for session");
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			s << tr("Transit tunnels enabled for session");
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			s << tr("Transit tunnels disabled for session");
		else if (cmd == HTTP_COMMAND_SETLANGUAGE)
			s << tr("Console language updated");
		else if (cmd == HTTP_COMMAND_LOGLEVEL)
			s << tr("Log level updated for session");
		else
			s << "<b>" << tr("SUCCESS") << "</b>:&nbsp;" << tr("Command accepted");
		s << "</td></tr>\r\n";
		res.add_header("Refresh", redirect.c_str());
	}

	void HTTPConnection::SendReply (HTTPRes& reply, std::string& content)
	{
		reply.add_header("X-Frame-Options", "SAMEORIGIN");
		reply.add_header("X-Content-Type-Options", "nosniff");
		reply.add_header("X-XSS-Protection", "1; mode=block");
		reply.add_header("Content-Type", "text/html");
		reply.body = content;

		m_SendBuffer = reply.to_string();
		boost::asio::async_write (*m_Socket, boost::asio::buffer(m_SendBuffer),
			std::bind (&HTTPConnection::Terminate, shared_from_this (), std::placeholders::_1));
	}

	HTTPServer::HTTPServer (const std::string& address, int port):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port)),
		m_Hostname(address)
	{
	}

	HTTPServer::~HTTPServer ()
	{
		Stop ();
	}

	void HTTPServer::Start ()
	{
		bool needAuth;    i2p::config::GetOption("http.auth", needAuth);
		std::string user; i2p::config::GetOption("http.user", user);
		std::string pass; i2p::config::GetOption("http.pass", pass);
		/* generate pass if needed */
		if (needAuth && pass == "") {
			uint8_t random[16];
			char alnum[] = "0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			pass.resize(sizeof(random));
			RAND_bytes(random, sizeof(random));
			for (size_t i = 0; i < sizeof(random); i++) {
				pass[i] = alnum[random[i] % (sizeof(alnum) - 1)];
			}
			i2p::config::SetOption("http.pass", pass);
			LogPrint(eLogInfo, "HTTPServer: password set to ", pass);
		}

		m_IsRunning = true;
		m_Thread.reset (new std::thread (std::bind (&HTTPServer::Run, this)));
		m_Acceptor.listen ();
		Accept ();

		LoadExtCSS();
	}

	void HTTPServer::Stop ()
	{
		m_IsRunning = false;
		m_Acceptor.close();
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			m_Thread = nullptr;
		}
	}

	void HTTPServer::Run ()
	{
		i2p::util::SetThreadName("Webconsole");

		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "HTTPServer: runtime exception: ", ex.what ());
			}
		}
	}

	void HTTPServer::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&HTTPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void HTTPServer::HandleAccept(const boost::system::error_code& ecode,
		std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		if (ecode)
		{
			if(newSocket) newSocket->close();
			LogPrint(eLogError, "HTTP Server: error handling accept ", ecode.message());
			if(ecode != boost::asio::error::operation_aborted)
				Accept();
			return;
		}
		CreateConnection(newSocket);
		Accept ();
	}

	void HTTPServer::CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		auto conn = std::make_shared<HTTPConnection> (m_Hostname, newSocket);
		conn->Receive ();
	}
} // http
} // i2p
