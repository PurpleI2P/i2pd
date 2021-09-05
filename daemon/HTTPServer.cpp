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
		"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%23405' rx='5'/%3E%3Ccircle cx='32' cy='32' r='4' fill='%23e580ff'/%3E%3Cg fill='%23d42aff'%3E%3Ccircle cx='20' cy='32' r='4'/%3E%3Ccircle cx='44' cy='32' r='4'/%3E%3Ccircle cx='32' cy='20' r='4'/%3E%3Ccircle cx='32' cy='44' r='4'/%3E%3C/g%3E%3Cg fill='%2380a'%3E%3Ccircle cx='20' cy='56' r='4'/%3E%3Ccircle cx='44' cy='8' r='4'/%3E%3Ccircle cx='44' cy='56' r='4'/%3E%3Ccircle cx='8' cy='44' r='4'/%3E%3Ccircle cx='56' cy='20' r='4'/%3E%3Ccircle cx='56' cy='44' r='4'/%3E%3Ccircle cx='8' cy='20' r='4'/%3E%3Ccircle cx='20' cy='8' r='4'/%3E%3C/g%3E%3Cg fill='%23aa00d4'%3E%3Ccircle cx='32' cy='56' r='4'/%3E%3Ccircle cx='44' cy='20' r='4'/%3E%3Ccircle cx='44' cy='44' r='4'/%3E%3Ccircle cx='8' cy='32' r='4'/%3E%3Ccircle cx='56' cy='32' r='4'/%3E%3Ccircle cx='32' cy='8' r='4'/%3E%3Ccircle cx='20' cy='44' r='4'/%3E%3Ccircle cx='20' cy='20' r='4'/%3E%3C/g%3E%3Cg fill='%23660080'%3E%3Ccircle cx='8' cy='56' r='4'/%3E%3Ccircle cx='56' cy='8' r='4'/%3E%3Ccircle cx='56' cy='56' r='4'/%3E%3Ccircle cx='8' cy='8' r='4'/%3E%3C/g%3E%3C/svg%3E";
	// Bundled style
	const std::string internalCSS =
		"<style title=\"purple royale\">\r\n"
":root{"
"--bodyfont:Open Sans,Noto Sans,Ubuntu,Segoe UI,sans-serif;"
"--monospaced:Droid Sans Mono,Noto Mono,Lucida Console,DejaVu Sans Mono,monospace;"
"--logo:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 19'%3E%3Cg fill='purple'%3E%3Ccircle cx='2.7' cy='2.6' r='1.2'/%3E%3Ccircle cx='2.7' cy='6' r='1.2'/%3E%3Ccircle cx='2.7' cy='9.5' r='1.2'/%3E%3Ccircle cx='2.7' cy='13' r='1.2'/%3E%3Ccircle cx='2.7' cy='16.4' r='1.2'/%3E%3Ccircle cx='9.6' cy='2.6' r='1.2'/%3E%3Ccircle cx='9.6' cy='6' r='1.2'/%3E%3Ccircle cx='9.6' cy='9.5' r='1.2'/%3E%3Ccircle cx='9.6' cy='13' r='1.2'/%3E%3Ccircle cx='9.6' cy='16.4' r='1.2'/%3E%3Ccircle cx='13' cy='6' r='1.2'/%3E%3Ccircle cx='16.5' cy='6' r='1.2'/%3E%3Ccircle cx='16.5' cy='13' r='1.2'/%3E%3Ccircle cx='19.9' cy='6' r='1.2'/%3E%3Ccircle cx='19.9' cy='13' r='1.2'/%3E%3Ccircle cx='23.4' cy='13' r='1.2'/%3E%3Ccircle cx='26.8' cy='2.6' r='1.2'/%3E%3Ccircle cx='26.8' cy='6' r='1.2'/%3E%3Ccircle cx='26.8' cy='9.5' r='1.2'/%3E%3Ccircle cx='26.8' cy='13' r='1.2'/%3E%3Ccircle cx='26.8' cy='16.4' r='1.2'/%3E%3Ccircle cx='33.7' cy='6' r='1.2'/%3E%3Ccircle cx='33.7' cy='13' r='1.2'/%3E%3Ccircle cx='33.7' cy='16.4' r='1.2'/%3E%3Ccircle cx='37.2' cy='6' r='1.2'/%3E%3Ccircle cx='37.2' cy='13' r='1.2'/%3E%3Ccircle cx='37.2' cy='16.4' r='1.2'/%3E%3Ccircle cx='40.6' cy='13' r='1.2'/%3E%3Ccircle cx='40.6' cy='16.4' r='1.2'/%3E%3Ccircle cx='44.1' cy='2.6' r='1.2'/%3E%3Ccircle cx='44.1' cy='6' r='1.2'/%3E%3Ccircle cx='44.1' cy='9.5' r='1.2'/%3E%3Ccircle cx='44.1' cy='13' r='1.2'/%3E%3Ccircle cx='44.1' cy='16.4' r='1.2'/%3E%3Ccircle cx='47.5' cy='2.6' r='1.2'/%3E%3Ccircle cx='47.5' cy='6' r='1.2'/%3E%3Ccircle cx='51' cy='2.6' r='1.2'/%3E%3Ccircle cx='51' cy='6' r='1.2'/%3E%3Ccircle cx='51' cy='13' r='1.2'/%3E%3Ccircle cx='54.4' cy='2.6' r='1.2'/%3E%3Ccircle cx='54.4' cy='6' r='1.2'/%3E%3Ccircle cx='54.4' cy='13' r='1.2'/%3E%3Ccircle cx='61.3' cy='2.6' r='1.2'/%3E%3Ccircle cx='61.3' cy='6' r='1.2'/%3E%3Ccircle cx='61.3' cy='9.5' r='1.2'/%3E%3Ccircle cx='61.3' cy='13' r='1.2'/%3E%3Ccircle cx='61.3' cy='16.4' r='1.2'/%3E%3C/g%3E%3Cg fill='%23f0f'%3E%3Ccircle cx='6.1' cy='2.6' r='1.2'/%3E%3Ccircle cx='6.1' cy='6' r='1.2'/%3E%3Ccircle cx='6.1' cy='9.5' r='1.2'/%3E%3Ccircle cx='6.1' cy='13' r='1.2'/%3E%3Ccircle cx='6.1' cy='16.4' r='1.2'/%3E%3Ccircle cx='13' cy='2.6' r='1.2'/%3E%3Ccircle cx='13' cy='9.5' r='1.2'/%3E%3Ccircle cx='13' cy='13' r='1.2'/%3E%3Ccircle cx='13' cy='16.4' r='1.2'/%3E%3Ccircle cx='16.5' cy='2.6' r='1.2'/%3E%3Ccircle cx='16.5' cy='9.5' r='1.2'/%3E%3Ccircle cx='16.5' cy='16.4' r='1.2'/%3E%3Ccircle cx='19.9' cy='2.6' r='1.2'/%3E%3Ccircle cx='19.9' cy='9.5' r='1.2'/%3E%3Ccircle cx='19.9' cy='16.4' r='1.2'/%3E%3Ccircle cx='23.4' cy='2.6' r='1.2'/%3E%3Ccircle cx='23.4' cy='6' r='1.2'/%3E%3Ccircle cx='23.4' cy='9.5' r='1.2'/%3E%3Ccircle cx='23.4' cy='16.4' r='1.2'/%3E%3Ccircle cx='30.3' cy='2.6' r='1.2'/%3E%3Ccircle cx='30.3' cy='6' r='1.2'/%3E%3Ccircle cx='30.3' cy='9.5' r='1.2'/%3E%3Ccircle cx='30.3' cy='13' r='1.2'/%3E%3Ccircle cx='30.3' cy='16.4' r='1.2'/%3E%3Ccircle cx='33.7' cy='2.6' r='1.2'/%3E%3Ccircle cx='33.7' cy='9.5' r='1.2'/%3E%3Ccircle cx='37.2' cy='2.6' r='1.2'/%3E%3Ccircle cx='37.2' cy='9.5' r='1.2'/%3E%3Ccircle cx='40.6' cy='2.6' r='1.2'/%3E%3Ccircle cx='40.6' cy='6' r='1.2'/%3E%3Ccircle cx='40.6' cy='9.5' r='1.2'/%3E%3Ccircle cx='47.5' cy='9.5' r='1.2'/%3E%3Ccircle cx='47.5' cy='13' r='1.2'/%3E%3Ccircle cx='47.5' cy='16.4' r='1.2'/%3E%3Ccircle cx='51' cy='9.5' r='1.2'/%3E%3Ccircle cx='51' cy='16.4' r='1.2'/%3E%3Ccircle cx='54.4' cy='9.5' r='1.2'/%3E%3Ccircle cx='54.4' cy='16.4' r='1.2'/%3E%3Ccircle cx='57.9' cy='2.6' r='1.2'/%3E%3Ccircle cx='57.9' cy='6' r='1.2'/%3E%3Ccircle cx='57.9' cy='9.5' r='1.2'/%3E%3Ccircle cx='57.9' cy='13' r='1.2'/%3E%3Ccircle cx='57.9' cy='16.4' r='1.2'/%3E%3C/g%3E%3C/svg%3E\");"
"--dropdown:url(\"data:image/svg+xml,%3Csvg viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='m5.29 17.93 26.71 28.14 26.71-28.14' fill='none' stroke='%23ae6ba8' stroke-linecap='round' stroke-linejoin='round' stroke-width='10'/%3E%3C/svg%3E\");"
"--dropdown_hover:url(\"data:image/svg+xml,%3Csvg viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='m5.29 17.93 26.71 28.14 26.71-28.14' fill='none' stroke='%23fafafa' stroke-linecap='round' stroke-linejoin='round' stroke-width='10'/%3E%3C/svg%3E\");"
"--yes:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cpath fill='%2371c837' d='M55.9 8.6a4.3 4.3 0 00-3 1.3l-31 30.8L11.3 30a4.4 4.4 0 00-6 0l-4 4.2a4.4 4.4 0 000 6L19 57.7a4.4 4.4 0 006 0l37.8-37.9a4.4 4.4 0 000-6l-4-4a4.3 4.3 0 00-3-1.3z'/%3E%3C/svg%3E\");"
"--yes_btn:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cpath fill='%23ae6ba8' d='M55.9 8.6a4.3 4.3 0 00-3 1.3l-31 30.8L11.3 30a4.4 4.4 0 00-6 0l-4 4.2a4.4 4.4 0 000 6L19 57.7a4.4 4.4 0 006 0l37.8-37.9a4.4 4.4 0 000-6l-4-4a4.3 4.3 0 00-3-1.3z'/%3E%3C/svg%3E\");"
"--no:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cpath fill='red' d='M9.7 0c-1 0-2.1.4-3 1.2L1.3 7a4.2 4.2 0 000 5.8L20.6 32 1.3 51.3a4.2 4.2 0 000 5.9l5.6 5.6a4.2 4.2 0 005.9 0L32 43.5l19.2 19.3a4.2 4.2 0 005.9 0l5.6-5.6a4.2 4.2 0 000-5.9L43.5 32l19.2-19.3a4.1 4.1 0 000-5.9l-5.6-5.6a4.2 4.2 0 00-5.8 0L32 20.5 12.6 1.2A4.2 4.2 0 009.7 0z'/%3E%3C/svg%3E\");"
"--info:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cpath fill='%23fcf' stroke='%23313' d='M31.4 3a28.8 28.8 0 00-1.6.1 28.8 28.8 0 00-26.6 29 28.8 28.8 0 1057.6 0A28.8 28.8 0 0031.4 3zm.6 9.3a4.5 4.5 0 014.5 4.5 4.5 4.5 0 01-4.5 4.4 4.5 4.5 0 01-4.5-4.4 4.5 4.5 0 014.5-4.5zm-4.5 13.1h9v26.3h-9V25.4z'/%3E%3C/svg%3E\");"
"--eye:url(\"data:image/svg+xml,%3Csvg viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='m63.95 33.1a2.03 2.03 0 0 0 0-1.97c-6.13-11.3-18.1-18.95-31.85-18.95s-25.7 7.66-31.85 18.94a2.03 2.03 0 0 0 0 1.97c6.13 11.3 18.1 18.95 31.85 18.95s25.7-7.67 31.85-18.95z' fill='%23894c84'/%3E%3Cpath d='m32.1 47.4c-8.45 0-15.3-6.85-15.3-15.3s6.85-15.3 15.3-15.3 15.3 6.85 15.3 15.3-6.85 15.3-15.3 15.3z' fill='%23313'/%3E%3Cpath d='m32.1 24.3a7.72 7.72 0 0 0 -1.87.22 4.05 4.05 0 0 1 .99 2.65c0 2.24-1.8 4.04-4.04 4.04-1 0-1.93-.37-2.65-1a7.66 7.66 0 0 0 -.22 1.87 7.79 7.79 0 0 0 7.79 7.79c4.3 0 7.8-3.5 7.8-7.8s-3.5-7.8-7.8-7.8z' fill='%23894c84'/%3E%3C/svg%3E\");"
"--eye_hover:url(\"data:image/svg+xml,%3Csvg viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='m63.95 33.1a2.03 2.03 0 0 0 0-1.97c-6.13-11.3-18.1-18.95-31.85-18.95s-25.7 7.66-31.85 18.94a2.03 2.03 0 0 0 0 1.97c6.13 11.3 18.1 18.95 31.85 18.95s25.7-7.67 31.85-18.95z' fill='%23dbd'/%3E%3Cpath d='m32.1 47.4c-8.45 0-15.3-6.85-15.3-15.3s6.85-15.3 15.3-15.3 15.3 6.85 15.3 15.3-6.85 15.3-15.3 15.3z' fill='%23313'/%3E%3Cpath d='m32.1 24.3a7.72 7.72 0 0 0 -1.87.22 4.05 4.05 0 0 1 .99 2.65c0 2.24-1.8 4.04-4.04 4.04-1 0-1.93-.37-2.65-1a7.66 7.66 0 0 0 -.22 1.87 7.79 7.79 0 0 0 7.79 7.79c4.3 0 7.8-3.5 7.8-7.8s-3.5-7.8-7.8-7.8z' fill='%23dbd'/%3E%3C/svg%3E\");"
"--arrow_left:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%23dbd' viewBox='0 0 64 64'%3E%3Cpath d='M4.5 32l30-30v20.2h25v19.6h-25V62z'/%3E%3C/svg%3E\");"
"--arrow_right:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%23dbd' viewBox='0 0 64 64'%3E%3Cpath d='M59.5 32l-30-30v20.2h-25v19.6h25V62z'/%3E%3C/svg%3E\");"
"--arrow_up:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%23dbd' viewBox='0 0 64 64'%3E%3Cpath d='M32 4.5l-30 30h20.2v25h19.6v-25H62z'/%3E%3C/svg%3E\");"
"--arrow_down:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%23dbd' viewBox='0 0 64 64'%3E%3Cpath d='M32 59.5l-30-30h20.2v-25h19.6v25H62z'/%3E%3C/svg%3E\");"
"--arrow_double:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%23dbd' viewBox='0 0 64 64'%3E%3Cpath d='M2.4 32l20.9-20.9v14h6.3v13.7h-6.3v14zM61.6 32L40.7 11.1v14h-6.3v13.7h6.3v14z'/%3E%3C/svg%3E\");"
"--error:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cg stroke-linejoin='round'%3E%3Cpath fill='none' stroke='%23300' stroke-width='10' d='M58 54.6H6l26-45z'/%3E%3Cpath fill='%23fff' stroke='%23b00' stroke-width='3' d='M58 54.6H6l26-45z'/%3E%3C/g%3E%3Cpath d='M29.5 24.5h5v14.7h-5zm0 18.6h5v5.6h-5z'/%3E%3C/svg%3E\");"
"--success:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='32' fill='%2371c837'/%3E%3Ccircle cx='32' cy='32' r='27.1' fill='%23fff'/%3E%3Ccircle cx='32' cy='32' r='22.2' fill='%2371c837'/%3E%3Cpath fill='%23fff' d='M44 19.4a2.2 2.2 0 00-1.5.6L27 35.5 21.6 30c-.8-.8-2.3-.8-3 0l-2.1 2.1c-.8.8-.7 2.2 0 3l9 8.9c.8.8 2.2.8 3 0l19-19c.8-.8.8-2.3 0-3l-2-2a2.2 2.2 0 00-1.5-.7z'/%3E%3C/svg%3E\");"
"--planet:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='32' fill='%231ea6c6'/%3E%3Cpath fill='%23f7cf52' d='M59.5 15.6c-5-3.6-6.9-1.8-7.6-.3a2 2 0 01-1.8 1.1h-.2a2 2 0 01-1.9-2c0-4.2 2.7-8.4 2.7-8.4a32.1 32.1 0 018.8 9.6zM64 32a32 32 0 01-1.9 10.8c-1-1.7-1.4-3.8-1.5-5.6-.1-2-2-3.5-4-3.2a5 5 0 01-5.7-4.3 19.4 19.4 0 01-.2-3.4s.4-4.9 2.8-7.2a4 4 0 011.2-1.1 2.5 2.5 0 011.8-.5c2.3.3 4 0 4 0A31.9 31.9 0 0164 32zM37.2 5.3l-3.9 5c-.5-3.8-5-7.1-3.9-7 6 .5 7.8 2 7.8 2zm-8 5.3a3.2 3.2 0 01-1.3 4.8 26.1 26.1 0 00-8.5 5.6 3 3 0 01-3 1c-1.5-.3-3.4-.3-4.5 1.6-2 3.6 5.8 7.6 5.4 12a3.6 3.6 0 00-2.1-2.4c-2.8-1.2-5.2-3-6.8-5.9C5 21.1 7.4 13.7 9.8 9a32 32 0 0110.3-6.6s5.3 3.3 9 8.3zm7.5 31c3 1.7 3.7 5.8 1.4 8.5l-4 4.7-5 5.3-3.3 3.3c-3-4.3-2-12.5-2-12.5l-3-2.2a7.6 7.6 0 01-3.3-7 17 17 0 00-.2-6c2.6-.8 5.3-1.2 7.2-1.4a5 5 0 014 1.3c2 2 5.4 4.2 8.2 6z'/%3E%3C/svg%3E\");"
"--tunnel:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' viewBox='0 0 64 64'%3E%3Cdefs%3E%3Cpath id='A' fill-opacity='.8' d='M0 0h32v32H0z'/%3E%3C/defs%3E%3ClinearGradient id='B' gradientUnits='userSpaceOnUse'%3E%3Cstop offset='0' stop-color='%23ff0'/%3E%3Cstop offset='.6' stop-color='%23f7cc22'/%3E%3Cstop offset='1' stop-color='%23d4aa00'/%3E%3C/linearGradient%3E%3CradialGradient id='C' cx='282.7' cy='938.5' r='184.6' gradientTransform='matrix(-.19558 -.1369 -.05868 .07823 153.4 13)' xlink:href='%23B'/%3E%3Cfilter id='D' width='1' height='1' x='0' y='0'%3E%3CfeColorMatrix in='SourceGraphic' values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 1 0'/%3E%3C/filter%3E%3CradialGradient id='E' cx='413' cy='807.7' r='151.1' gradientTransform='matrix(-.17603 0 0 .19558 97.6 -124.9)' xlink:href='%23B'/%3E%3CradialGradient id='F' cx='306.1' cy='1055.1' r='184.6' gradientTransform='matrix(-.21514 0 0 .07823 107.6 -30.2)' gradientUnits='userSpaceOnUse'%3E%3Cstop offset='0' stop-color='%23a80'/%3E%3Cstop offset='.8' stop-color='%23a28100'/%3E%3Cstop offset='1' stop-color='%23540'/%3E%3C/radialGradient%3E%3Cmask id='G'%3E%3Cg filter='url(%23D)'%3E%3Cuse fill-opacity='.5' xlink:href='%23A'/%3E%3C/g%3E%3C/mask%3E%3CradialGradient id='H' cx='478.2' cy='713.7' r='76.4' gradientTransform='matrix(-.12 .21 .13 .07 -27.3 -142.6)' gradientUnits='userSpaceOnUse'%3E%3Cstop offset='0' stop-color='%23fff'/%3E%3Cstop offset='1' stop-color='%23fff' stop-opacity='0'/%3E%3C/radialGradient%3E%3CclipPath id='I'%3E%3Cuse xlink:href='%23A'/%3E%3C/clipPath%3E%3Cpath d='M50.3 24.7c1 3.3 1.5 6 2 8.6 4 3.8 10.2 10 10.5 12.4.2 2.4-9.7 11-14.1 12-3 1-10.8.4-19.8-2.5-8.2-2.5-16-6-23.2-10.7-2.8-2-4.5-4.4-4.5-7 0-2.4 1.2-4.6 3.1-6L4.1 29A22.1 22.1 0 0125.8 6.1c14.2.5 21.6 9.6 24.5 18.6z'/%3E%3Cg transform='translate(.2 .1)'%3E%3Cpath fill='url(%23C)' d='M49 25.1c1 3.2 1.4 5.9 1.8 8.2l2.1 1.8c2 1.6 8.4 8 8.4 10.2 0 2.7-5.8 6.4-8.2 8.4-3.3 2.5-4.3 3-11.5 3A91 91 0 016.9 43.4c-2.6-2-4-3.9-4-6.4 0-2 1-4 3-5.5L5.5 29a21 21 0 0120-21.7A24.8 24.8 0 0149 25z'/%3E%3Cpath fill='url(%23E)' d='M50.8 33.3C50.7 45 35.4 47.8 28.4 48 18.2 48 5.7 40.8 5.7 31.6V29c9.2-34.5 39.1-17.5 45.1 4.3z'/%3E%3Cpath fill='url(%23F)' d='M3 36.5c.2 2.1 2.4 4.4 4.8 6.2a101 101 0 0033.7 13c4.2.3 8-.6 11.3-3.1 3.4-2.7 8-5 8.6-7.5.4 2.8-5.7 6.6-8.1 8.6a15 15 0 01-11.8 3A89 89 0 016.9 43.5c-2.7-2-4.1-4.3-4.1-6.4v-.6z'/%3E%3C/g%3E%3Cpath d='M46.9 29.7v1.4C45.7 19.6 31.3 4.8 18.3 8.6c2-.6 4.1-1 6.4-1C36.3 7.8 47 19.4 47 29.7z'/%3E%3Cpath d='M20.3 8.2c8.6 2 16 11.3 17.6 23.8.4 3.4.4 6.7 0 9.8 0-2.5 0-5-.4-7.8-2-13.7-10.3-24-19.5-24.9zm0 0'/%3E%3Cg clip-path='url(%23I)' mask='url(%23G)' transform='matrix(1.95584 0 0 1.95584 .6 .8)'%3E%3Cpath fill='url(%23H)' d='M11 5.6c2.1 1.8 3.8 4.3 5 7.3a28.5 28.5 0 00-12.3 1c-.2-4.7 3-8.2 7.4-8.3zm0 0'/%3E%3C/g%3E%3C/svg%3E\");"
"--established:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%233b3' d='M17.4 2.5l3.4 7c.3.3.7.7 1.3.8l7.5 1c1.3.2 1.9 2 1 2.8L25 19.4c-.4.4-.5 1-.4 1.5l1.2 7.5a1.6 1.6 0 01-2.3 1.7l-6.7-3.5c-.5-.3-1.1-.3-1.5 0L8.5 30c-1.3.7-2.6-.3-2.4-1.7L7.4 21c0-.6 0-1.1-.5-1.5l-5.4-5.3a1.6 1.6 0 01.9-2.8l7.5-1c.5 0 1-.4 1.3-.9l3.4-6.9c.5-1.1 2.2-1.1 2.8 0z'/%3E%3C/svg%3E\");"
"--building:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23dd0' d='M17.4 2.5l3.4 7c.3.3.7.7 1.3.8l7.5 1c1.3.2 1.9 2 1 2.8L25 19.4c-.4.4-.5 1-.4 1.5l1.2 7.5a1.6 1.6 0 01-2.3 1.7l-6.7-3.5c-.5-.3-1.1-.3-1.5 0L8.5 30c-1.3.7-2.6-.3-2.4-1.7L7.4 21c0-.6 0-1.1-.5-1.5l-5.4-5.3a1.6 1.6 0 01.9-2.8l7.5-1c.5 0 1-.4 1.3-.9l3.4-6.9c.5-1.1 2.2-1.1 2.8 0z'/%3E%3C/svg%3E\");"
"--failed:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23f00' d='M17.4 2.5l3.4 7c.3.3.7.7 1.3.8l7.5 1c1.3.2 1.9 2 1 2.8L25 19.4c-.4.4-.5 1-.4 1.5l1.2 7.5a1.6 1.6 0 01-2.3 1.7l-6.7-3.5c-.5-.3-1.1-.3-1.5 0L8.5 30c-1.3.7-2.6-.3-2.4-1.7L7.4 21c0-.6 0-1.1-.5-1.5l-5.4-5.3a1.6 1.6 0 01.9-2.8l7.5-1c.5 0 1-.4 1.3-.9l3.4-6.9c.5-1.1 2.2-1.1 2.8 0z'/%3E%3C/svg%3E\");"
"--expiring:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23999999dd' d='M17.4 2.5l3.4 7c.3.3.7.7 1.3.8l7.5 1c1.3.2 1.9 2 1 2.8L25 19.4c-.4.4-.5 1-.4 1.5l1.2 7.5a1.6 1.6 0 01-2.3 1.7l-6.7-3.5c-.5-.3-1.1-.3-1.5 0L8.5 30c-1.3.7-2.6-.3-2.4-1.7L7.4 21c0-.6 0-1.1-.5-1.5l-5.4-5.3a1.6 1.6 0 01.9-2.8l7.5-1c.5 0 1-.4 1.3-.9l3.4-6.9c.5-1.1 2.2-1.1 2.8 0z'/%3E%3C/svg%3E\");"
"--exploratory:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3CradialGradient id='a' cx='-23' cy='27.6' r='15.6' gradientUnits='userSpaceOnUse'%3E%3Cstop offset='0' stop-color='%2364b5f6'/%3E%3Cstop offset='1' stop-color='%237bc9ff'/%3E%3C/radialGradient%3E%3Cg transform='matrix(.62496 0 0 .62496 1 1)'%3E%3Cg fill='%23616161' transform='matrix(-1.1993 0 0 1.1993 52.8 -4.8)'%3E%3Cpath d='M29.2 32l2.8-2.8 12 12-2.8 2.8z'/%3E%3Ccircle cx='20' cy='20' r='16'/%3E%3C/g%3E%3Cpath fill='%2337474f' d='M9.7 41.6l-3.3-3.3L0 44.7 3.3 48z'/%3E%3Ccircle cx='-28.8' cy='19.2' r='15.6' fill='url(%23a)' transform='scale(-1 1)'/%3E%3Cpath fill='%23bbdefb' fill-opacity='.9' d='M20.5 9.9a10.8 10.8 0 0116.6 0c.4.4.3 1.3-.2 1.6-.4.5-1.3.4-1.6 0a8.5 8.5 0 00-13 0c-.2.2-.6.4-1 .4l-.7-.2c-.5-.5-.5-1.4-.1-1.8z'/%3E%3C/g%3E%3C/svg%3E\");"
"--local:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3ClinearGradient id='a' x1='7.8' x2='23.1' y1='10.4' y2='33.3' gradientUnits='userSpaceOnUse'%3E%3Cstop offset='0' stop-color='%23ffd5f6'/%3E%3Cstop offset='1' stop-color='%23fae'/%3E%3C/linearGradient%3E%3Cpath fill='%239d93ac' d='M35.2 44.9l1 7.6h-8.4l1-7.6z'/%3E%3Cpath fill='%23beb7c8' d='M60 46c0 1.3-1.1 2.4-2.4 2.4H6.4A2.4 2.4 0 014 46V10c0-1.3 1.1-2.4 2.4-2.4h51.2c1.3 0 2.4 1 2.4 2.4zm-37 6.2h18a2 2 0 012 2v.2a2 2 0 01-2 2H23a2 2 0 01-2-2v-.2a2 2 0 012-2z'/%3E%3Ccircle cx='32' cy='44.8' r='1.3' fill='%23dedbe3'/%3E%3Cpath fill='%23de87cd' d='M8.1 12v29.3h48.1V12z'/%3E%3Cpath fill='url(%23a)' d='M7.5 12.5v29l49-29z' transform='matrix(.98 0 0 1.01 .7 -.6)'/%3E%3Cpath fill='none' stroke='%23442178' stroke-width='2' d='M8 12v29.3h48V12z'/%3E%3C/svg%3E\");"
"--time:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cg transform='translate(1 1)'%3E%3Ccircle cx='31.1' cy='31.1' r='28.1' stroke='%23dbd' stroke-width='6'/%3E%3Cpath fill='none' stroke='%23dbd' stroke-linecap='round' stroke-linejoin='round' stroke-width='5' d='M30.7 13.2v18.5h16.5'/%3E%3Ccircle cx='31.1' cy='31.1' r='4.5' fill='%23dbd'/%3E%3C/g%3E%3C/svg%3E\");"
"--tag:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cpath fill='%23dbd' d='M63 37.9v20.3c-.2 2.3-2.6 4.5-4.9 4.7l-20.3.1a4.3 4.3 0 01-2.9-1.4L2.3 29.2a4.3 4.3 0 010-6.1L23.1 2.3a4.3 4.3 0 016.1 0l32.5 32.5c.9.8 1.3 1.9 1.3 3.2zm-9.3 5.5a7.3 7.3 0 10-10.3 10.2 7.3 7.3 0 0010.3 0 7.1 7.1 0 000-10.2z'/%3E%3C/svg%3E\");"
"--shutdown:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23717' d='M16 1a3 3 0 00-3 3v9.3a3 3 0 002.9 2.9 3 3 0 003-2.8V4a3 3 0 00-3-3zm7.2 3.2a3 3 0 00-2.8 3 3 3 0 001.1 2.2 8.8 8.8 0 013.3 6.9 8.8 8.8 0 01-9.9 8.8 8.8 8.8 0 01-4.5-15.7 3 3 0 001-2.2c0-2.4-2.7-3.8-4.6-2.3a14.6 14.6 0 00-5.5 12.9 14.7 14.7 0 1023.9-13 2.8 2.8 0 00-1.9-.6z'/%3E%3C/svg%3E\");"
"--shutdown_hover:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23900' d='M16 1a3 3 0 00-3 3v9.3a3 3 0 002.9 2.9 3 3 0 003-2.8V4a3 3 0 00-3-3zm7.2 3.2a3 3 0 00-2.8 3 3 3 0 001.1 2.2 8.8 8.8 0 013.3 6.9 8.8 8.8 0 01-9.9 8.8 8.8 8.8 0 01-4.5-15.7 3 3 0 001-2.2c0-2.4-2.7-3.8-4.6-2.3a14.6 14.6 0 00-5.5 12.9 14.7 14.7 0 1023.9-13 2.8 2.8 0 00-1.9-.6z'/%3E%3C/svg%3E\");"
"--scrollbar:#414 #101;"
"--ink:#dbd;"
"--ink-darker:#b9b;"
"--ink-faded:rgba(221,187,221,.5);"
"--notify:#5f5;"
"--page:#120012;"
"--main-boxshadow:0 0 0 1px var(--border),0 0 0 2px #000,0 0 0 4px #313,0 0 0 5px #101,0 0 0 6px #000;"
"--link:#ae6ba8;"
"--link_hover:#fafafa;"
"--border:#515;"
"--border2:#404;"
"--button-border:#313;"
"--button:linear-gradient(#303,#202 50%,#202 50%,#101);"
"--button_hover:linear-gradient(to bottom,#94518e,#733f6f 50%,#733f6f 50%,#42243f);"
"--button_active:linear-gradient(to bottom,#202,#303);"
"--active_shadow:inset 3px 3px 3px rgba(0,0,0,.8);"
"--hr:linear-gradient(to right,#313,#414,#313);"
"--highlight:inset 0 0 0 1px #101;"
"--tr:#180818;"
"--tr-alt:#202;"
"--tr-inner:#240024;"
"--header:linear-gradient(to bottom,#202,#101 50%,#101 50%,#000);"
"--th:linear-gradient(to bottom,#180018,#080008);"
"--th_multicolumn:linear-gradient(to bottom,#202,#101);"
"--sectiontitle:linear-gradient(to bottom,#240024,#140014 50%,#140014 50%,#080008);"
"--section:linear-gradient(to bottom,rgba(0,0,0,.5),rgba(8,0,8,.5));"
"--b64:#101;"
"--b64-ink:#2475c2;"
"--b64-boxshadow:0 0 0 1px #000,inset 0 0 0 1px #202;"
"--input_text:var(--button-border);"
"--menu:#303;"
"--menu-ink:#fff;"
"--textshadow:0 1px 1px rgba(0,0,0.7)}"
"html,body{min-height:100%;background:var(--page)}"
"html,body,textarea{scrollbar-color:var(--scrollbar)}"
"body{margin:0;padding:0;width:100%;height:100%;display:table;line-height:1.6;position:absolute;top:0;left:0;text-align:center;font:14pt var(--bodyfont);color:var(--ink);background:radial-gradient(circle at center,rgba(48,0,48,.3),rgba(0,0,0,.05)),linear-gradient(to bottom,rgba(0,0,0,.3),rgba(32,0,32,.6),rgba(0,0,0,.3)), var(--page)}"
".wrapper{margin:0 auto;padding:5px;width:100%;display:table-cell;vertical-align:middle;text-align:center}"
".header{display:inline-block;width:100%;vertical-align:middle;position:relative}"
"#shutdownbutton{position:absolute;top:0;right:-10px;display:inline-block;width:40px;height:44px;font-size:0;background:var(--shutdown) no-repeat center center / 24px}"
"#shutdownbutton:hover,#shutdownbutton:focus{background:var(--shutdown_hover) no-repeat center center / 24px}"
"#shutdownbutton:active{transform:scale(.85)}"
"#shutdownbutton:active[data-tooltip]::after{display:none}"
"b{font-weight:600}"
"#main{margin:0 auto;min-width:300px;max-width:700px;font-size:85%;border:2px solid var(--border);border-spacing:1px;box-shadow:var(--main-boxshadow)}"
".center,.center form,.register{text-align:center!important}"
".left{text-align:left!important}"
".right{text-align:right!important}"
"form{margin:5px 0}"
"a,.slide label{text-decoration:none;color:var(--link);font-weight:600}"
".slide label{font-weight:700}"
".count{margin:-1px 0 -1px 3px;padding:0 10px;display:inline-block;vertical-align:baseline;font-size:85%;border-radius:2px;background:var(--ink-darker);color:var(--page);text-shadow:none}"
"label:hover .count{background:var(--ink)}"
"a{padding:1px 8px;display:inline-block;border-radius:2px}"
".listitem a{padding:0 1px}"
"a#home{width:calc(100% - 20px);height:44px;display:inline-block;font-size:0;background:var(--logo) no-repeat center center / auto 40px;opacity:.5;vertical-align:top}"
"a#home:hover{opacity:1}"
"a.view{padding-left:0;color:var(--ink);width:100%}"
"a.view:hover,a.view:focus,tr:active .view{padding-left:22px;color:var(--link);background:var(--eye) no-repeat left center / 16px}"
"a:hover,.slide label:hover,button:hover,select:hover,input[type=number]:focus,td.streamid:hover{color:var(--link_hover);background:var(--link)}"
"a.button,button,input,select{vertical-align:middle}"
"select,input,button{margin:4px 2px;padding:6px 8px;font-family:var(--bodyfont);font-size:90%!important;font-weight:600;color:var(--link);border:1px solid var(--button-border);-moz-appearance:none;-webkit-appearance:none;appearance:none}"
"a,select,button,label{text-shadow:var(--textshadow);cursor:pointer}"
"a.button,button{margin:4px 2px;padding:2px 8px 4px;min-width:64px;display:inline-block;font-size:90%!important;font-weight:700;text-align:center;text-decoration:none;border:1px solid var(--button-border);border-radius:2px;box-shadow:var(--highlight);background:var(--button);appearance:none}"
"a.button{margin:8px 2px}"
"button{padding:6px 12px;min-width:120px}"
"a.button:hover,a.button:focus{color:var(--link_hover);background:var(--button_hover)!important}"
"button:active,a.button:active,.slide label:active,td.streamid:active{box-shadow:var(--highlight),var(--active_shadow);background:var(--button_active)!important}"
".streamid:hover a{color:var(--link_hover)}"
"button.apply{padding:7px 12px 6px;color:transparent;text-shadow:none!important;background:var(--yes_btn) no-repeat center center / 14px,var(--button)}"
"button.apply:hover,button.apply:focus{color:transparent;background:var(--yes) no-repeat center center / 14px,var(--button_hover)!important}"
"button.apply:active{color:transparent;background:var(--yes) no-repeat center center / 14px,var(--button_active)!important;background-blend-mode:luminosity}"
"select,input[type=number]{width:150px;box-sizing:border-box;font-size:90%!important;background:var(--input_text)}"
"input[type=number]{box-shadow:var(--highlight),var(--active_shadow);outline:none;appearance:none;-moz-appearance:textfield}"
"input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none}"
"select{padding:6px 20px 6px 8px;line-height:1.5;background:var(--dropdown) no-repeat right 8px center / 10px,var(--button);box-shadow:var(--highlight)}"
"select:hover,select:focus,select:active{color:var(--link_hover);background:var(--dropdown_hover) no-repeat right 8px center / 10px,var(--button_hover)}"
"select option{color:var(--menu-ink);background:var(--menu)}"
"select,option:hover,option:focus,option:active{outline:none}"
".note{margin:0 -6px;padding:15px 12px!important;font-size:95%;border:1px solid #414;background:radial-gradient(at bottom center,rgba(48,8,48,.3),rgba(0,0,0,0) 70%),linear-gradient(to bottom,rgba(32,0,32,.2),rgba(24,0,24,.2));box-shadow:inset 0 0 0 1px rgba(96,0,96,.2),0 0 0 1px #000}"
".note::before{margin:-3px 2px 0 -2px;width:24px;height:18px;display:inline-block;vertical-align:middle;background:var(--info) no-repeat center center / 16px;content:\"\"}"
".routerservice{display:inline-block;margin:4px 2px;padding:0 10px 0 25px;background:#303 var(--yes) no-repeat 8px center / 10px;border-radius:2px;text-align:left;font-size:90%}"
"table{background:repeating-linear-gradient(to bottom,rgba(24,0,24,.3) 2px,rgba(48,0,48,.3) 4px),repeating-linear-gradient(to right,rgba(48,0,48,.8) 2px,rgba(24,0,24,.5) 4px),linear-gradient(to bottom,#240024,#200020);background-size:100% 4px,4px 100%,100%}"
"tr{border-top:1px solid var(--border);border-bottom:1px solid var(--border)}"
"tr#version,tr#version ~ tr:nth-child(odd),tr.chrome,.listitem:nth-child(odd){background:linear-gradient(to bottom,rgba(16,0,16,.5),rgba(8,0,8,.5))}"
"tr#version ~ tr:nth-child(even),.listitem:nth-child(even){background:linear-gradient(to bottom,rgba(32,0,32,.5),rgba(24,0,24,.5))}"
"tr tr,/*tr#version,tr#version ~ tr:nth-child(odd),*/ .tableitem tr:nth-child(odd){background:var(--tr-inner)!important}"
".tableitem tr:nth-child(even){background:var(--tr)!important}"
"th,td,.listitem{box-shadow:var(--highlight);font-size:97%}"
"th,td{padding:5px 12px;border:1px solid var(--button-border)}"
"th{padding:6px 12px;font-weight:600;background:var(--th_multicolumn)}"
"th:not(.sectiontitle)[colspan=\"2\"],#routerservices{background:linear-gradient(to right,rgba(0,0,0.6),rgba(0,0,0,0),rgba(0,0,0,.6)),var(--th);background:linear-gradient(to right,rgba(0,0,0,.4),rgba(0,0,0,0),rgba(0,0,0,.4)),rgba(32,0,32,.4)}"
"th:not(.sectiontitle)[colspan=\"2\"],.slide label{font-size:95%}"
"th.sectiontitle{padding:0 0 10px!important;font-weight:700;border-bottom:none}"
".sectiontitle span{padding:4px 12px;min-width:50%;display:inline-block;white-space:nowrap;line-height:1.6;font-size:98%;border:1px solid var(--button-border);border-top:none;border-radius:0 0 4px 4px;box-shadow:var(--highlight),0 2px 2px rgba(0,0,0,.4);background:radial-gradient(at top center,rgba(64,16,64,.4),rgba(0,0,0,0) 50%),var(--sectiontitle)}"
"table table th{font-size:80%}"
"tr:first-child{background:var(--header)}"
"td:first-child{width:50%;text-align:right;font-weight:600}"
"td td:first-child{width:auto}"
"td:last-child{text-align:left}"
".listitem,.tableitem{padding:5px 0;white-space:nowrap;font-size:80%;font-family:var(--monospaced)}"
".listitem{display:inline-block;width:100%;vertical-align:middle;border-top:1px solid var(--button-border)}"
".listitem:last-child{border-bottom:1px solid var(--button-border)}"
".listitem.out .arrowup,.listitem.in .arrowdown{margin:3px 8px 0 16px;float:left}"
".error,.notify{padding:30px 12px 40px;font-size:110%;color:#fff;box-shadow:var(--highlight),inset 0 0 3px 3px rgba(0,0,0,.6);text-align:center;background:linear-gradient(to bottom,rgba(32,0,32,.5),rgba(4,0,4,.7))}"
".toast + .toast {display: none}"
"#warning,#success{margin:-5px 0 10px;width:100%;height:48px;display:block;background:var(--error) no-repeat center top / 44px}"
"#success{background:var(--success) no-repeat center top / 40px}"
".thin{width:1%;white-space:nowrap}"
"#navlinks{padding:10px 2px!important;font-size:100%;background:var(--header)}"
"#navlinks a:hover{background:var(--button_hover)}"
"#navlinks a:active{color:var(--ink-faded);box-shadow:var(--highlight),var(--active_shadow),0 0 0 1px var(--button-border);background:var(--button_active)}"
".enabled,.disabled{font-size:0;display:inline-block;width:10px;height:10px;vertical-align:middle}"
"#main .enabled{background:var(--yes) no-repeat left 12px center / 10px}"
"#main .disabled{background:var(--no) no-repeat left 12px center / 10px}"
".sensitive{filter:blur(8px);display:inline-block!important;max-width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.05;font-size:75%}"
".sensitive:hover,td:active .sensitive{max-width:300px;white-space:pre-wrap;word-break:break-all;filter:blur(0)}"
".arrowright,.arrowleft,.arrowleftright,.arrowup,.arrowdown{width:12px;height:16px;display:inline-block;vertical-align:middle;font-size:0!important}"
".arrowleft{background:var(--arrow_left) no-repeat center center / 11px}"
".arrowright{background:var(--arrow_right) no-repeat center center / 11px}"
".arrowleftright{background:var(--arrow_double) no-repeat center center / 11px}"
".arrowup{background:var(--arrow_up) no-repeat center center / 12px}"
".arrowdown{background:var(--arrow_down) no-repeat center center / 12px}"
".tableitem .button{margin:0!important;padding:1px 4px!important;font-size:100%!important;border:none;background:none;box-shadow:none}"
".streamid .button,.streamid .button:hover,.streamid .button:focus,.streamid .button:active{background:none!important;box-shadow:none!important}"
".tableitem a.button .close{margin:-2px -6px 0 0;width:11px;height:11px;display:inline-block;vertical-align:middle;color:transparent!important;text-shadow:none!important;background:var(--no) no-repeat center center / 9px!important;opacity:.8}"
".tableitem a.button:hover .close,.tableitem a.button:focus .close{opacity:1}"
".tunnel.established{color:#56B734}"
".tunnel.expiring{color:#D3AE3F}"
".tunnel.failed{color:#D33F3F}"
".tunnel.building{color:#434343}"
"caption{font-size:1.5em;text-align:center;color:var(--link)}"
"table{display:table;border-collapse:collapse;text-align:center}"
"td table{width:100%!important}"
"table.extaddr{text-align:left}"
"table.services{width:100%}"
"#b64{margin:2px -4px;padding:3px 4px;width:calc(100% + 8px);word-break:break-all;color:var(--b64-ink);border:1px solid var(--button-border);background:var(--b64);font-family:var(--monospaced);font-size:80%;display:inline-block;line-height:1;box-sizing:border-box;user-select:all;box-shadow:var(--b64-boxshadow);white-space:pre-wrap;margin:4px;width:calc(100% - 8px);text-align:justify}"
".streamdest{width:120px;max-width:240px;overflow:hidden;text-overflow:ellipsis}"
".slide div.slidecontent,.slide [type=checkbox]{display:none}"
".slide [type=checkbox]:checked ~ div.slidecontent{margin-top:0;padding:0;display:block}"
".disabled{color:#D33F3F}"
".enabled{color:#56B734}"
".nopadding{padding:0!important}"
".nopadding table{border:none!important}"
".tunnelid.local,.tunnel{display:inline-block;width:16px;height:16px;vertical-align:middle;font-size:0;background:var(--local) no-repeat center center / 16px}"
".tunnelid:not(.local){padding:2px 4px 0 22px;display:inline-block;width:auto;height:16px;vertical-align:middle;border-radius:2px;box-shadow:0 0 0 1px #000;background:#303 var(--tunnel) no-repeat 4px center / 14px;text-align:left;min-width:86px;border-left:5px solid var(--border2);border-radius:0 2px 2px 0}"
".tunnel{margin:1px 5px 0;width:26px;height:16px;float:left;vertical-align:middle;background:var(--established) no-repeat left center / 12px}"
".tunnelid.local + .tunnel{margin-left:4px}"
".tunnel.building{background:var(--building) no-repeat left center / 12px}"
".tunnel.failed{background:var(--failed) no-repeat left center / 12px}"
".tunnel.expiring{background:var(--expiring) no-repeat left center / 12px}"
".tunnel.exploratory{background:var(--established) no-repeat left center / 12px,var(--exploratory) no-repeat right 3px / 12px}"
".tunnel.building.exploratory{background:var(--building) no-repeat left center / 12px,var(--exploratory) no-repeat right 3px / 12px}"
".tunnel.expiring.exploratory{background:var(--expiring) no-repeat left center / 12px,var(--exploratory) no-repeat right 3px / 12px}"
".tunnel.failed.exploratory{background:var(--failed) no-repeat left center / 12px,var(--exploratory) no-repeat right 3px / 12px}"
"span[data-tooltip]{position:relative}"
".hops{text-align:right}"
".hop,.host{padding:1px 4px;display:inline-block;vertical-align:middle;border-radius:2px;box-shadow:0 0 0 1px #000;background:#303}"
".chain.inbound .arrowright:not(.zerohop):first-of-type{display:none!important}"
".host{padding-left:17px;background:#303 var(--planet) no-repeat 4px center / 9px}"
"a[href^=\"https://gwhois\"]:hover,a[href^=\"https://gwhois\"]:focus{background:none!important}"
"a:hover .host,a:focus .host,a:active .host{background:#505 var(--exploratory) no-repeat 2px center / 13px}"
".transferred{display:inline-block;vertical-align:middle;text-align:right}"
".latency{padding:2px 5px 2px 20px;min-width:40px;display:inline-block;vertical-align:middle;text-align:right;float:right;background:var(--page) var(--time) no-repeat 5px center / 13px;border-radius:2px}"
".latency.unknown{color:var(--ink-faded)}"
".sent,.recvd{padding-right:16px;display:inline-block;vertical-align:middle;text-align:right;background:var(--arrow_up) no-repeat right center / 12px}"
".recvd{background:var(--arrow_down) no-repeat right center / 12px}"
".hide{display:none}"
".router.sent,.router.recvd,.transit.sent{padding-left:17px;padding-right:0;text-align:left;background-size:14px;background-position:left center}"
".router.sent{margin-left:6px}"
".itag{padding-left:13px;display:inline-block;vertical-align:middle;background:var(--tag) no-repeat left center / 10px}"
"a[href^=\"https://gwhois\"]{position:relative}"
"span[data-tooltip]:hover::after,span[data-tooltip]:active::after,.itag[data-tooltip]:hover::after,.itag[data-tooltip]:active::after,.header a[data-tooltip][href*=\"cmd\"]:hover::after{padding:3px 6px;display:inline-block;position:absolute;top:-32px;left:-10px;font-size:12px;font-weight:600;color:#444;border:1px solid #444;box-shadow:0 0 1px 1px rgba(0,0,0,.2);background:#fff!important;content:attr(data-tooltip);text-shadow:none!important;white-space:nowrap}"
".header a[data-tooltip][href*=\"cmd\"]:hover::after{top:auto;right:-8px;bottom:42px;left:auto}"
".slide label{margin:0;padding:6px 0 6px 20px;width:100%;display:block;border:1px solid var(--button-border);border-left:none;border-right:none;box-shadow:var(--highlight);background:var(--button);background:var(--th);background:linear-gradient(to bottom,rgba(48,8,48,.5),rgba(0,0,0,.8));box-sizing:border-box;color:var(--ink)}"
"input[type=checkbox] + label::after{content:\"+\";display:inline-block;vertical-align:middle;float:right;margin:-6px 10px 2px 0;font-size:16pt;font-weight:700;color:var(--ink);opacity:.7}"
"input[type=checkbox]:checked + label::after{content:\"–\"}"
".slide label:hover{color:var(--link_hover);background:var(--button_hover);opacity:.9}"
".slide label:active::after {transform: scale(.9)}"
".slide table{width:100%}"
"@media screen and (max-width: 1000px) {"
"body{font-size:13pt!important}"
".listitem{font-size:90%}"
"a{padding:1px 3px}"
".b32,.listitem a[href*=\"local_destination&b32\"]{max-width:300px;display:inline-block;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}"
".router.sent,.router.recvd,.transit.sent{padding-left:15px;background-size:12px}"
".tunnelid:not(.local){display:none}"
".tunnel,.latency{margin:1px 6px 0 4px}"
".tunnel,.hops{margin-top:2px;display:inline-block;vertical-align:middle}"
"}"
"@media screen and (-webkit-min-device-pixel-ratio: 1.5) {"
"body{font-size:12pt!important}"
".i2ptunnels .b32,.i2cp .b32{max-width:200px!important}"
"}"
"@media screen and (max-width: 800px) {"
"#main{width:400px}"
"td{padding:5px 10px}"
"td:first-child{width:auto}"
".b32,.listitem a[href*=\"local_destination&b32\"]{max-width:300px}"
".arrowup,.arrowdown,.tunnel{float:none}"
".latency{min-width:0;background-size:11px;background-color:transparent!important}"
".hop{margin:0 -3px}"
"}"
"@media screen and (-webkit-min-device-pixel-ratio: 1.5) {"
"#main{width:300px}"
"}"
"@media screen and (min-width: 1000px) {"
".tunnelid[data-tooltip]:hover::after,.tunnelid[data-tooltip]:active::after{display:none}"
".hops{display:inline-block;min-width:240px}"
"}"
"@media screen and (min-width: 1200px) {"
"#main{width:700px}"
"#navlinks a{margin-top:0;margin-bottom:0}"
".tunnelid{background-size:16px}"
".tunnelid:not(.local),.latency,.hops{margin-top:1px;margin-bottom:-1px}"
".tunnelid:not(.local){margin-left:12px;float:right}"
".chain{min-width:560px;display:inline-block;vertical-align:middle}"
"#transports .chain{min-width:580px;text-align:left}"
".chain.transit{min-width:0;text-align:center}"
".hops{min-width:280px;display:inline-block;text-align:right}"
".recvd,.sent{min-width:64px}"
".router.recvd,.router.sent{min-width:80px}"
".host{min-width:144px}"
".host a{margin-bottom:-1px}"
".SSU .host{min-width:190px}"
".i2ptunnels .listitem a{padding:2px 10px;min-width:100px;text-align:right}"
".i2ptunnels .listitem a:hover,.i2ptunnels .listitem a:focus{text-align:center}"
".listitem.out .arrowup,.listitem.in .arrowdown{margin-top:2px;background-size:14px}"
".i2ptunnels .b32{margin-right:10px}"
".itag,.host{margin-top:1px}"
".itag{padding:2px 5px 2px 20px;float:right;min-width:100px;display:inline-block;border-radius:2px;background-color:var(--menu);background-position:5px center}"
".latency{padding-top:3px;padding-bottom:3px;margin-left:12px}"
".transferred{min-width:48px}"
".tunnel{margin:2px 0 0 -48px}"
"}"
"@media screen and (min-width: 1200px) and (min-height: 600px) {"
".wrapper{padding:2%}"
"td,.listitem,.tableitem{padding-top:6px;padding-bottom:6px}"
".host,.hop{padding-top:2px;padding-bottom:2px}"
".tunnelid:not(.local){padding-top:3px;padding-bottom:1px}"
"}"
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

	const char HTTP_PAGE_TUNNEL_SUMMARY[] = "tunnel_summary";
	const char HTTP_PAGE_LOCAL_TUNNELS[] = "local_tunnels";
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
		snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d.%03lld",
			tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, divTime.rem);
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
			LogPrint(eLogError, "HTTPServer: Unknown loglevel set attempted");
			return;
		}
		i2p::log::Logger().Reopen ();
	}

	static void ShowPageHead (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		// Page language
		std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage(); // get current used language
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

		s << "<!DOCTYPE html>\r\n"
			 "<html lang=\"" << langCode << "\">\r\n"
			 "<head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
			 "<meta charset=\"UTF-8\">\r\n"
			 "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
			 "<link rel=\"shortcut icon\" href=\"" << i2pdfavicon << "\">\r\n"
			 "<title>Purple I2P | " VERSION "</title>\r\n";
		GetStyles(s);
		s << "</head>\r\n"
			 "<body>\r\n"
			 "<div class=\"wrapper\">\r\n<table id=\"main\">\r\n"
			 "<tr id=\"header\"><td class=\"center\" colspan=\"2\"><span class=\"header\">"
			 "<a id=\"home\" href=\"" << webroot << "\">" << tr("Main page") << "</a> "
			 // TODO placeholder for graceful shutdown button (requires token)
			 "<a id=\"shutdownbutton\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_SHUTDOWN_START << "&amp;token=" << token << "\" data-tooltip=\""
		  << tr("Start graceful shutdown") << "\">Shutdown</a>";
		// placeholder for toggle transit (requires token)
		if (i2p::context.AcceptsTunnels ()) {
			s << "<a id=\"disabletransit\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_DISABLE_TRANSIT << "&amp;token=" << token
			  << "\" data-tooltip=\"" << tr("Decline transit tunnels")
			  << "\">No transit</a>";
		} else {
			s << "<a id=\"enabletransit\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_ENABLE_TRANSIT << "&amp;token=" << token
			  << "\" data-tooltip=\"" << tr("Accept transit tunnels")
			  << "\">Accept transit</a>";
		}
		s << "</span></td></tr>\r\n"
		  << "<tr id=\"nav\"><td id=\"navlinks\" class=\"center\" colspan=\"2\">\r\n";
		if (i2p::context.IsFloodfill ())
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LEASESETS << "\">" << tr("LeaseSets") << "</a>\r\n";
		s << "<a title=\"" << tr("Local destinations currently active") << "\" href=\"" << webroot << "?page="
		  << HTTP_PAGE_LOCAL_DESTINATIONS << "\">" << tr("Destinations") << "</a>\r\n"
//			 "<a title=\"" << tr("Local Service Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_I2P_TUNNELS << "\">" << tr("Services") << "</a>\r\n"
//			 "<a title=\"" << tr("Active Transit Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">" << tr("Transit") << "</a>\r\n"
			 "<a title=\"" << tr("Router Transports and associated connections") << "\" href=\"" << webroot <<
			 "?page=" << HTTP_PAGE_TRANSPORTS << "\">" << tr ("Transports") << "</a>\r\n"
			 "<a title=\"" << tr("All active tunnels") << "\" href=\"" << webroot << "?page="
		  << HTTP_PAGE_TUNNEL_SUMMARY << "\">" << tr("Tunnels") << "</a>\r\n";
		if (sam && sam->GetSessions ().size ()) {
			s << "<a title=\"" << tr("Current SAM sessions") << "\" href=\"" << webroot << "?page="
			  << HTTP_PAGE_SAM_SESSIONS << "\">" << tr("SAM Sessions") << "</a>\r\n";
		}
		s << "<a title=\"" << tr("Router control and temporary configuration") << "\" href=\"" << webroot
		  << "?page=" << HTTP_PAGE_COMMANDS << "\">" << tr("Control") << "</a>\r\n</td></tr>\r\n";
	}

	static void ShowPageTail (std::stringstream& s)
	{
		s << "</table>\r\n"
			 "</div>\r\n"
			 "</body>\r\n"
			 "</html>\r\n";
	}

	static void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<tr class=\"toast\"><td class=\"center error\" colspan=\"2\"><span class=\"container\"><span id=\"warning\"></span>\r\n<b>" << tr("ERROR")
		  << ":</b>&nbsp;" << string << "</span></td></tr>\r\n";
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
			s << "<tr><td>" << tr("Shutdown") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#elif defined(WIN32_APP)
		if (i2p::win32::g_GracefulShutdownEndtime != 0) {
			uint16_t remains = (i2p::win32::g_GracefulShutdownEndtime - GetTickCount()) / 1000;
			s << "<tr><td>" << tr("Shutdown") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#endif
		s << "<tr><td>" << tr("Bandwidth") << "</td><td><span class=\"router recvd\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetInBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetInBandwidth () < 1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetInBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetInBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span> <span class=\"hide\">/</span> <span class=\"router sent\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetOutBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetOutBandwidth () < 1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetOutBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span>";

		if ((i2p::context.AcceptsTunnels() || i2p::tunnel::tunnels.CountTransitTunnels()) &&
			(i2p::transport::transports.GetTotalReceivedBytes () > 0)) {
			if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024*1024 ||
				i2p::transport::transports.GetTransitBandwidth () < 1024)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			s << " <span class=\"hide\">/</span> <span class=\"transit sent\" data-tooltip=\"";
			s << tr("Transit bandwidth usage") << "\">";
			s << (double) i2p::transport::transports.GetTransitBandwidth () / 1024;
			s << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s") << "</span>";
		}

		s << "</td></tr>\r\n";
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
		s << "</span>";

		if ((i2p::context.AcceptsTunnels() || i2p::tunnel::tunnels.CountTransitTunnels()) &&
			(i2p::transport::transports.GetTotalReceivedBytes () > 0)) {
			s << " <span class=\"hide\">/</span> <span class=\"transit sent\" data-tooltip=\"";
			s << tr("Total transit data transferred") << "\">";
			s << std::fixed << std::setprecision(0);
			if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024*1024)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			ShowTraffic (s, i2p::transport::transports.GetTotalTransitTransmittedBytes ());
			s << std::fixed << std::setprecision(0);
			s << "</span>";
		}
		s << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Build Success") << "</td><td>";
		s << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%</td></tr>\r\n";
		s << "<tr><td>" << tr("Routers") << "</td><td>" << i2p::data::netdb.GetNumRouters () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Floodfills") << "</td><td>" << i2p::data::netdb.GetNumFloodfills () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("LeaseSets") << "</td><td>" << i2p::data::netdb.GetNumLeaseSets () << "</td></tr>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		if (!(i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels()))
			s << "<tr id=\"last\">";
		else
			s << "<tr>";
		s << "<td>" << tr("Local Tunnels") << "</td><td>" << std::to_string(clientTunnelCount) << "</td></tr>\r\n";
		if (i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels()) {
			s << "<tr id=\"last\"><td>" << tr("Transit Tunnels") << "</td><td>"
			  << std::to_string(i2p::tunnel::tunnels.CountTransitTunnels()) << "</td></tr>\r\n";
		}

		if(outputFormat==OutputFormatEnum::forWebConsole) {
			bool httpproxy  = i2p::client::context.GetHttpProxy ()         ? true : false;
			bool socksproxy = i2p::client::context.GetSocksProxy ()        ? true : false;
			bool bob        = i2p::client::context.GetBOBCommandChannel () ? true : false;
			bool sam        = i2p::client::context.GetSAMBridge ()         ? true : false;
			bool i2cp       = i2p::client::context.GetI2CPServer ()        ? true : false;
			bool i2pcontrol;  i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
			if (httpproxy || socksproxy || bob || sam || i2cp || i2pcontrol) {
				s << "<tr class=\"center sectiontitle configuration\">"
				  << "<th colspan=\"2\"><span>" << tr("Router Services") << "</span>\r\n";
				s << "<div id=\"routerservices\" class=\"center\">";
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
					s << " <span class=\"routerservice\">I2PControl</span>";
				s << "</div>\r\n</th></tr>\r\n";
			}
		}

			s << "</tbody>\r\n";
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Client Destinations")
		  << "</span></th></tr>\r\n<tr><td class=\"center nopadding\" colspan=\"2\"><div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n" << std::endl;
		}
		s << "</div>\r\n</td></tr>\r\n";

		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer && !(i2cpServer->GetSessions ().empty ()))
		{
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>I2CP " << tr("Server Destinations")
			  << "</span></th></tr>\r\n<tr><td class=\"center nopadding i2cp\" colspan=\"2\"><div class=\"list\">\r\n";
			for (auto& it: i2cpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					auto& name = dest->GetNickname ();
					s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_I2CP_LOCAL_DESTINATION << "&i2cp_id=" << it.first << "\">[ ";
					s << name << " ]</a> <span class=\"arrowleftright\">&#8660;</span> <span class=\"b32\">"
					  << i2p::client::context.GetAddressBook ().ToAddress(ident) <<"</span></div>\r\n" << std::endl;
				}
			}
			s << "</div>\r\n</td></tr>\r\n";
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
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << dest->GetNumRemoteLeaseSets ()
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
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
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
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumSentBytes ());
				s << "</span></div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";

		if (dest->GetNumIncomingTags () > 0) {
			s << "<tr><th colspan=\"2\">" << tr("Incoming Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">"
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
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Outgoing Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << out_tags
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n"
			  << "<tr><td class=\"center nopadding\" colspan=\"2\"><table>\r\n"
			  << "<thead>\r\n<tr><th class=\"left\">" << tr("Destination") << "</th><th class=\"thin\">" << tr("Count")
			  << "</th></thead>\r\n<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</td></tr>\r\n";
		} else
			s << "<tr><th colspan=\"2\">" << tr("No Outgoing Session Tags") << "</th></tr>\r\n";

		auto numECIESx25519Tags = dest->GetNumIncomingECIESx25519Tags ();
		if (numECIESx25519Tags > 0) {
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>ECIESx25519</span></th></tr>";
			s << "<tr><th colspan=\"2\">" << tr("Incoming Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << numECIESx25519Tags
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
				  << " <span class=\"hide\">[</span><span class=\"badge\">" << ecies_sessions
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
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Destination")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << b32Short
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";
		} else
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Destination")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << tr("Not Found")
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";

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
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Tunnels") << "</span></th><tr>\r\n";
		s << "<tr><th colspan=\"2\">" << tr("Queue size") << ": " << i2p::tunnel::tunnels.GetQueueSize () << "</th></tr>\r\n";

		auto ExplPool = i2p::tunnel::tunnels.GetExploratoryPool ();

		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels_exploratory\" />\r\n"
		  << "<label for=\"slide_tunnels_exploratory\">" << tr("Exploratory Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">" << "in/out"
			  << "</span><span class=\"hide\">]</span></label>\r\n"; // TODO: separate client & exploratory tunnels into sections and flag individual services?
		s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			if (it->GetTunnelPool () == ExplPool) {
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
		}
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			if (it->GetTunnelPool () == ExplPool) {
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
				s << "</span>\r\n</div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n";


		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels_service\" />\r\n"
		  << "<label for=\"slide_tunnels_service\">" << tr("Service Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">" << "in/out"
			  << "</span><span class=\"hide\">]</span></label>\r\n"; // TODO: flag individual services by name
		s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			if (it->GetTunnelPool () != ExplPool) {
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
		}
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			if (it->GetTunnelPool () != ExplPool) {
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
				s << "</span>\r\n</div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
	}

	void ShowTunnelSummary (std::stringstream& s) {
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
        size_t localInCount = i2p::tunnel::tunnels.CountInboundTunnels();
        size_t localOutCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		size_t transitCount = i2p::tunnel::tunnels.CountTransitTunnels();
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Tunnel Summary") << "</span></th></tr>\r\n";
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<table id=\"tunnelsummary\">\r\n<thead>"
		  << "<tr><th>" << tr("Type") << "</th>"
		  << "<th class=\"in\">" << tr("Inbound") << "</th><th class=\"out\">" << tr("Outbound") << "</th>"
		  << "<th>" << tr("View Details") << "</th></tr></thead>\r\n";
		s << "<tr><td>" << tr("Local") << "</td><td class=\"in\">" << localInCount << "</td><td class=\"out\">" << localOutCount << "</td>"
		  << "<td><a class=\"button\" href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_TUNNELS << "\">View</a></td></tr>\r\n";
		if (transitCount > 0) {
		s << "<tr><td>" << tr("Transit") << "</td><td colspan=\"2\">" << transitCount << "</td>"
		  << "<td><a class=\"button\" href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">View</a></td></tr>\r\n";
		}
		s << "</table>\r\n";
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">";
		ShowI2PTunnels (s);
		s << "</td></tr>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_routerinfo\" />\r\n"
		  << "<label for=\"slide_routerinfo\">i2pd " VERSION "</label>\r\n";
		s << "<div class=\"slidecontent\">\r\n<table id=\"routerinfos\">\r\n";
		s << "<tr><td>" << tr("Router Identity") << "</td><td class=\"nopadding\"><span id=\"rid\">"
		  << i2p::context.GetRouterInfo().GetIdentHashBase64() << "</span></td></tr>\r\n";
		s << "<tr><td>" << tr("Router Caps") << "</td><td>" << i2p::context.GetRouterInfo().GetProperty("caps") << "</td></tr>\r\n";
		if (!i2p::context.GetRouterInfo().GetProperty("family").empty())
			s << "<tr><td>" << tr("Router Family") << "</td><td>"
			  << i2p::context.GetRouterInfo().GetProperty("family") << "</td></tr>\r\n";
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<tr><td>"<< tr("Family") << "</td><td>" << family << "<br>\r\n";
		for (const auto& address : i2p::context.GetRouterInfo().GetAddresses())
		{
			s << "<tr>\r\n";
			if (address->IsNTCP2 () && !address->IsPublishedNTCP2 ())
			{
				s << "<td>NTCP2";
				if (address->host.is_v6 ()) s << "v6";
				s << "</td><td><span class=\"enabled fixedsize\">" << tr("supported") << "</span></td>\r\n</tr>\r\n";
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
			s << "<td>" << address->host.to_string() << ":" << address->port << "</td>\r\n</tr>\r\n";
		}
		s << "<tr><td>" << tr("Uptime") << "</td><td>";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Data path") << "</td><td>" << i2p::fs::GetUTF8DataDir() << "</td></tr>\r\n";
		s << "</table>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";


		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Router Commands") << "</span>"
		  << "<div id=\"commands\" class=\"chrome\">\r\n";

		std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
		if (i2p::fs::Exists(styleFile)) {
		s << "<a id=\"reloadcss\" class=\"cmd\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_RELOAD_CSS << "&token=" << token
		  << "\" data-tooltip=\"" << tr("Reload external CSS stylesheet") << "\">"
		  << tr("Reload external CSS stylesheet") << "</a>";
		}

		s << "  <a id=\"testpeer\" class=\"cmd\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token
		  << "\" data-tooltip=\"" << tr("Run peer test") << "\">"
		  << tr("Run peer test") << "</a><br>\r\n";

		// s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << "\">Reload config</a><br>\r\n";

		if (i2p::context.AcceptsTunnels ())
			s << "  <a id=\"transitdecline\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Decline transit tunnels") << "\">"
			  << tr("Decline transit tunnels") << "</a><br>\r\n";
		else
			s << "  <a id=\"transitaccept\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Accept transit tunnels") << "\">"
			  << tr("Accept transit tunnels") << "</a><br>\r\n";

		if (i2p::tunnel::tunnels.CountTransitTunnels()) {
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			if (Daemon.gracefulShutdownInterval)
				s << "  <a id=\"shutdowncancel\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Cancel graceful shutdown") << "\">"
				  << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a id=\"shutdowngraceful\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Start graceful shutdown") << "\">"
				  << tr("Start graceful shutdown") << "</a><br>\r\n";
#elif defined(WIN32_APP)
			if (i2p::util::DaemonWin32::Instance().isGraceful)
				s << "  <a id=\"shutdowncancel\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Cancel graceful shutdown") << "\">"
				  << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a id=\"shutdowngraceful\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Start graceful shutdown") << "\">"
				  << tr("Start graceful shutdown") << "</a><br>\r\n";
#endif
			s << "  <a id=\"shutdownforce\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Force shutdown") << "\">"
			  << tr("Force shutdown") << "</a></th></tr>\r\n";

/* TODO graceful shutdown button in header with .notify dialog if transit tunnels
   active to offer option to shutdown immediately
   only one option? displayed in the header
*/
		} else {
			s << "  <a id=\"shutdownforce\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Shutdown") << "\">"
			  << tr("Shutdown") << "</a>";
		}
		s << "</div></th></tr>\r\n";
		s << "<tr class=\"chrome notice\"><td class=\"center\" colspan=\"2\">\r\n<div class=\"note\">"
		  << tr("<b>Note:</b> Configuration changes made here persist for the duration of the router session and will not be saved to your config file.")
		  << "</div>\r\n</td></tr>";

		const LogLevel loglevel = i2p::log::Logger().GetLogLevel();
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Logging Level") << "</span>\r\n";
		s << "<div id=\"loglevel\" class=\"chrome\">";
		s << "<a class=\"button" << (loglevel == 0 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=none&token=" << token << "\">none</a>\r\n";
		s << "<a class=\"button" << (loglevel == 1 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=error&token=" << token << "\">error</a>\r\n";
		s << "<a class=\"button" << (loglevel == 2 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=warn&token=" << token << "\">warn</a>\r\n";
		s << "<a class=\"button" << (loglevel == 3 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=info&token=" << token << "\">info</a>\r\n";
		s << "<a class=\"button" << (loglevel == 4 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=debug&token=" << token << "\">debug</a>"
		  << "</div>\r\n</th></tr>\r\n";

		if (i2p::context.AcceptsTunnels ()) {
			uint16_t maxTunnels = GetMaxNumTransitTunnels ();
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Maximum Transit Tunnels") << "</span>\r\n";
			s << "<div id=\"maxtransit\" class=\"chrome\">\r\n";
			s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_LIMITTRANSIT << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
			s << "  <input type=\"number\" min=\"0\" max=\"65535\" name=\"limit\" value=\"" << maxTunnels << "\">\r\n";
			s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
			s << "</form>\r\n</div>\r\n</th></tr>\r\n";
		}

		std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage(); // get current used language
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Console Display Language") << "</span>\r\n";
		s << "<div id=\"consolelang\" class=\"chrome\">\r\n";
		s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_SETLANGUAGE << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
		s << "  <select name=\"lang\" id=\"lang\">\r\n";
		for (const auto& it: i2p::i18n::languages)
			s << "    <option value=\"" << it.first << "\"" << ((it.first.compare(currLang) == 0) ? " selected" : "") << ">" << it.second.LocaleName << "</option>\r\n";
		s << "  </select>\r\n";
		s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
		s << "</form>\r\n</div>\r\n</th></tr>\r\n";

	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		if(i2p::tunnel::tunnels.CountTransitTunnels())
		{
			int count = i2p::tunnel::tunnels.GetTransitTunnels().size();
			s << "<tr class=\"sectiontitle configuration\"><th colspan=\"2\"><span>" << tr("Transit Tunnels");
			s << " <span class=\"hide\">[</span><span class=\"badge\">" << count << "</span><span class=\"hide\">]</span>"
			  << "</span></th></tr>";
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div ";
			if (count > 7)
				s << "id=\"transit\" ";
			s << "class=\"list\">\r\n";
			for (const auto& it: i2p::tunnel::tunnels.GetTransitTunnels ())
			{
				const auto& expiry = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout ();
				s << "<div class=\"listitem\"><span class=\"chain transit\">";

				double bytes = it->GetNumTransmittedBytes ();
				s << std::fixed << std::setprecision(0);
				if (bytes > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<span class=\"sent\">" << (double) (bytes / 1024 / 1024 / 1024) << "G</span> ";
				} else if (bytes > 1024 * 1024) {
					s << std::fixed << std::setprecision(1);
					s << "<span class=\"sent\">" << (double) (bytes / 1024 / 1024) << "M</span> ";
				} else if (bytes > 1024) {
					s << "<span class=\"sent\">" << (int) (bytes / 1024) << "K</span> ";
				} else {
					s << "<span class=\"sent\">" << (int) (bytes) << "B</span> ";
				}
				// TODO: tunnel expiry per tunnel, not most recent
				//s << "<span class=\"expiry\">" << expiry << tr("s" /* translation: seconds */) << "</span> ";
				s << "<span class=\"tunnelid\">" << it->GetTunnelID () << "</span> ";
				if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
					s << "<span class=\"role ibgw\" data-tooltip=\"" << tr("inbound gateway") << "\">"
					  << tr("inbound gateway") << "</span>";
				else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
					s << "<span class=\"role obep\"data-tooltip=\"" << tr("outbound endpoint") << "\">"
					  << tr("outbound endpoint") << "</span>";
				else
					s << "<span class=\"role ptcp\" data-tooltip=\"" << tr("participant") << "\">"
					  << tr("participant") << "</span>";
				s << "</div>\r\n";
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
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << cnt
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s.str () << "</div>\r\n</div>\r\n";
		}
		if (!tmp_s6.str ().empty ())
		{
			s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\" />\r\n"
			  << "<label for=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\">" << name
			  << "v6 <span class=\"hide\">[</span><span class=\"badge\">" << cnt6
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s6.str () << "</div>\r\n</div>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Transports") << "</span></th></tr>\r\n"
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
				  << "<label for=\"slide_ssu\">SSU <span class=\"hide\">[</span><span class=\"badge\">"
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
				  << "<label for=\"slide_ssuv6\">SSUv6 <span class=\"hide\">[</span><span class=\"badge\">"
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
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("SAM sessions")
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
		s << "<tr class=\"sectiontitle\"><th colspan=\"4\"><span>" << tr("Service Tunnels") << "</span></th></tr>";
		s << "<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_client_tunnels\" />\r\n"
		  << "<label for=\"slide_client_tunnels\">" << tr("Client Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"client_tunnels\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
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
		s << "</div>\r\n</div>\r\n</div>\r\n";

		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_server_tunnels\" />\r\n"
			  << "<label for=\"slide_server_tunnels\">" << tr("Server Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">"
			  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
			s << "<div id=\"server_tunnels\" class=\"slidecontent list\">\r\n";
			s << "<div class=\"list\">\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowright\">&#8658;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</span></div>\r\n" << std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}

		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
		s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_client_forwards\" />\r\n"
		  << "<label for=\"slide_client_forwards\">" << tr("Client Forwards") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"client_forwards\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}
		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
		s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_server_forwards\" />\r\n"
		  << "<label for=\"slide_server_forwards\">" << tr("Server Forwards") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"server_forwards\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}
//		s << "</div></table>\r\n";
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

		LogPrint(eLogWarning, "HTTPServer: Auth failure from ", m_Socket->remote_endpoint().address ());
		return false;
	}

	void HTTPConnection::HandleRequest (const HTTPReq & req)
	{
		std::stringstream s;
		std::string content;
		HTTPRes res;

		LogPrint(eLogDebug, "HTTPServer: Request: ", req.uri);

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
		if (req.uri.find("summary") != std::string::npos ||
			req.uri.find("commands") != std::string::npos ||
			(req.uri.find("local_destinations") != std::string::npos &&
			 req.uri.find("b32") == std::string::npos))
			res.add_header("Refresh", "10");
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
			ShowStatus (s, true, i2p::http::OutputFormatEnum::forWebConsole);
			res.add_header("Refresh", "5");
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

		if (page == HTTP_PAGE_TRANSPORTS) {
			ShowTransports (s);
		} else if (page == HTTP_PAGE_TUNNEL_SUMMARY) {
			ShowTunnelSummary (s);
/*
			ShowTunnels (s);
			ShowI2PTunnels (s);
			ShowTransitTunnels (s);
*/
		} else if (page == HTTP_PAGE_COMMANDS) {
			uint32_t token = CreateToken ();
			ShowCommands (s, token);
		} else if (page == HTTP_PAGE_TRANSIT_TUNNELS) {
			ShowTransitTunnels (s);
		} else if (page == HTTP_PAGE_LOCAL_DESTINATIONS) {
			ShowLocalDestinations (s);
		} else if (page == HTTP_PAGE_LOCAL_DESTINATION) {
			uint32_t token = CreateToken ();
			ShowLocalDestination (s, params["b32"], token);
		} else if (page == HTTP_PAGE_I2CP_LOCAL_DESTINATION) {
			ShowI2CPLocalDestination (s, params["i2cp_id"]);
		} else if (page == HTTP_PAGE_SAM_SESSIONS) {
			ShowSAMSessions (s);
		} else if (page == HTTP_PAGE_SAM_SESSION) {
			ShowSAMSession (s, params["sam_id"]);
		} else if (page == HTTP_PAGE_LOCAL_TUNNELS) {
			ShowTunnels (s);
		} else if (page == HTTP_PAGE_LEASESETS) {
			ShowLeasesSets(s);
		} else {
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
						s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\2\">"
						  << "<span class=\"container\"><span id=\"success\"></span><b>" << tr("SUCCESS") << "</b>:&nbsp;"
						  << tr("Stream closed") << "</span></td></tr>\r\n";
					else
						s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
						  << "<span class=\"container\"><span id=\"warning\"></span>"
						  << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Stream not found or already was closed") << "</span></td></tr>\r\n";
				}
				else
					s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
					  << "<span class=\"container\"><span id=\"warning\"></span>"
					  << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Destination not found") << "</span></td></tr>\r\n";
			}
			else
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
				  << "<span class=\"container\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
				  << tr("StreamID can't be null") << "</span></td></tr>\r\n";

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
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
				  << "<span class=\"container\"><span id=\"warning\"></span>"
				  << tr("ERROR") << "</b>:&nbsp;"
				  << tr("Transit tunnels count must not exceed 65535") << "</span></td></tr>\r\n";
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
						s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\"2\"><span class=\"container\">"
						  << "<span id=\"success\"></span><b>" << tr("SUCCESS")
						  << "</b>:<br>\r\n<form action=\"http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/add\""
						  << " method=\"post\" rel=\"noreferrer\" target=\"_blank\">\r\n"
						  << "<textarea readonly name=\"record\" cols=\"80\" rows=\"10\">" << out.str () << "</textarea>\r\n<br>\r\n<br>\r\n"
						  << "<b>" << tr("Register at reg.i2p") << ":</b>\r\n<br>\r\n"
						  << "<b>" << tr("Description") << ":</b>\r\n<input type=\"text\" maxlength=\"64\" name=\"desc\" placeholder=\""
						  << tr("Short description of domain") << "\">\r\n"
						  << "<input type=\"submit\" value=\"" << tr("Submit") << "\">\r\n"
						  << "</form></span></td></tr>\r\n";
						delete[] signature;
						delete[] sig;
					}
					else
						s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\"><b>"
						  << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Domain can't end with .b32.i2p") << "</span></td></tr>\r\n";
				}
				else
					s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\">"
					  << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Domain must end with .i2p") << "</span></td></tr>\r\n";
			}
			else
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\">"
				  << tr("ERROR") << "</b>:&nbsp;"
				  << tr("No such destination found") << "</span></td></tr>\r\n";

//			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a>\r\n";
			return;
		}
		else if (cmd == HTTP_COMMAND_SETLANGUAGE)
		{
			std::string lang = params["lang"];
			std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage();

			if (currLang.compare(lang) != 0)
				i2p::i18n::SetLanguage(lang);
		}
		else if (cmd == HTTP_COMMAND_RELOAD_CSS)
		{
			std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
			if (i2p::fs::Exists(styleFile))
				LoadExtCSS();
			else
				ShowError(s, tr("No CSS file found on disk!"));
		}
		else
		{
			res.code = 400;
			ShowError(s, tr("Unknown command") + ": " + cmd);
			return;
		}


		s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\"2\"><span class=\"container\">"
		  << "<span id=\"success\"></span>";
		if (cmd == HTTP_COMMAND_SHUTDOWN_NOW)
			s << tr("Immediate router shutdown initiated");
		else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL)
			s << tr("Router shutdown cancelled");
		else if (cmd == HTTP_COMMAND_RELOAD_CSS) {
			s << tr("Console CSS stylesheet reloaded");
		} else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
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
		s << "</span></td></tr>\r\n";
		res.add_header("Refresh", redirect.c_str());
	}

	void HTTPConnection::SendReply (HTTPRes& reply, std::string& content)
	{
		reply.add_header("X-Frame-Options", "SAMEORIGIN");
		reply.add_header("X-Content-Type-Options", "nosniff");
		reply.add_header("X-XSS-Protection", "1; mode=block");
		reply.add_header("Content-Type", "text/html");
		reply.add_header("Server", "i2pd " VERSION " webconsole" );
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
			LogPrint(eLogInfo, "HTTPServer: Password set to ", pass);
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
			LogPrint(eLogError, "HTTP Server: Error handling accept ", ecode.message());
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
