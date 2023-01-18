/*
* Copyright (c) 2022, The PurpleI2P Project
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

// Simplified Chinese localization file
// This is an example translation file without strings in it.

namespace i2p
{
namespace i18n
{
namespace chinese // language namespace
{
	// language name in lowercase
	static std::string language = "chinese";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"%.2f KiB", "%.2f KiB"},
		{"%.2f MiB", "%.2f MiB"},
		{"%.2f GiB", "%.2f GiB"},
		{"building", "正在构建"},
		{"failed", "连接失败"},
		{"expiring", "即将过期"},
		{"established", "连接成功"},
		{"unknown", "未知"},
		{"exploratory", "探索"},
		{"Purple I2P Webconsole", "Purple I2P 网页控制台"},
		{"<b>i2pd</b> webconsole", "<b>i2pd</b> 网页控制台"},
		{"Main page", "主页"},
		{"Router commands", "路由命令"},
		{"Local Destinations", "本地目标"},
		{"LeaseSets", "租契集"},
		{"Tunnels", "隧道"},
		{"Transit Tunnels", "中转隧道"},
		{"Transports", "传输"},
		{"I2P tunnels", "I2P 隧道"},
		{"SAM sessions", "SAM 会话"},
		{"ERROR", "错误"},
		{"OK", "良好"},
		{"Testing", "测试中"},
		{"Firewalled", "受到防火墙限制"},
		{"Unknown", "未知"},
		{"Proxy", "代理"},
		{"Mesh", "Mesh组网"},
		{"Error", "错误"},
		{"Clock skew", "时钟偏移"},
		{"Offline", "离线"},
		{"Symmetric NAT", "对称 NAT"},
		{"Uptime", "运行时间"},
		{"Network status", "IPv4 网络状态"},
		{"Network status v6", "IPv6 网络状态"},
		{"Stopping in", "距停止还有："},
		{"Family", "家族"},
		{"Tunnel creation success rate", "隧道创建成功率"},
		{"Received", "已接收"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "已发送"},
		{"Transit", "中转"},
		{"Data path", "数据文件路径"},
		{"Hidden content. Press on text to see.", "隐藏内容 请点击此处查看。"},
		{"Router Ident", "路由身份"},
		{"Router Family", "路由器家族"},
		{"Router Caps", "路由器类型"},
		{"Version", "版本"},
		{"Our external address", "外部地址"},
		{"supported", "支持"},
		{"Routers", "路由节点"},
		{"Floodfills", "洪泛节点"},
		{"Client Tunnels", "客户端隧道"},
		{"Services", "服务"},
		{"Enabled", "启用"},
		{"Disabled", "禁用"},
		{"Encrypted B33 address", "加密的 B33 地址"},
		{"Address registration line", "地址域名注册"},
		{"Domain", "域名"},
		{"Generate", "生成"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>注意：</b> 结果字符串只能用于注册次级域名(例如：example.i2p)。若需注册子域名，请使用 i2pd-tools。"},
		{"Address", "地址"},
		{"Type", "类型"},
		{"EncType", "加密类型"},
		{"Inbound tunnels", "入站隧道"},
		{"%dms", "%d毫秒"},
		{"Outbound tunnels", "出站隧道"},
		{"Tags", "标签"},
		{"Incoming", "传入"},
		{"Outgoing", "传出"},
		{"Destination", "目标"},
		{"Amount", "数量"},
		{"Incoming Tags", "传入标签"},
		{"Tags sessions", "标签会话"},
		{"Status", "状态"},
		{"Local Destination", "本地目标"},
		{"Streams", "流"},
		{"Close stream", "断开流"},
		{"I2CP session not found", "未找到 I2CP 会话"},
		{"I2CP is not enabled", "I2CP 未启用"},
		{"Invalid", "无效"},
		{"Store type", "存储类型"},
		{"Expires", "过期时间"},
		{"Non Expired Leases", "未到期的租约"},
		{"Gateway", "网关"},
		{"TunnelID", "隧道 ID"},
		{"EndDate", "结束日期"},
		{"not floodfill", "非洪泛"},
		{"Queue size", "队列大小"},
		{"Run peer test", "运行节点测试"},
		{"Decline transit tunnels", "拒绝中转隧道"},
		{"Accept transit tunnels", "允许中转隧道"},
		{"Cancel graceful shutdown", "取消平滑关闭"},
		{"Start graceful shutdown", "平滑关闭"},
		{"Force shutdown", "强制停止"},
		{"Reload external CSS styles", "重载外部 CSS 样式"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>注意：</b> 此处完成的任何操作都不是永久的，不会更改您的配置文件。"},
		{"Logging level", "日志记录级别"},
		{"Transit tunnels limit", "中转隧道限制"},
		{"Change", "修改"},
		{"Change language", "更改语言"},
		{"no transit tunnels currently built", "目前未构建中转隧道"},
		{"SAM disabled", "SAM 已禁用"},
		{"no sessions currently running", "没有正在运行的会话"},
		{"SAM session not found", "未找到 SAM 会话"},
		{"SAM Session", "SAM 会话"},
		{"Server Tunnels", "服务器隧道"},
		{"Client Forwards", "客户端转发"},
		{"Server Forwards", "服务器转发"},
		{"Unknown page", "未知页面"},
		{"Invalid token", "无效令牌"},
		{"SUCCESS", "成功"},
		{"Stream closed", "流已关闭"},
		{"Stream not found or already was closed", "流未找到或已关闭"},
		{"Destination not found", "找不到目标"},
		{"StreamID can't be null", "StreamID 不能为空"},
		{"Return to destination page", "返回目标页面"},
		{"You will be redirected in 5 seconds", "您将在5秒内被重定向"},
		{"Transit tunnels count must not exceed 65535", "中转隧道数量不能超过 65535"},
		{"Back to commands list", "返回命令列表"},
		{"Register at reg.i2p", "在 reg.i2p 注册域名"},
		{"Description", "描述"},
		{"A bit information about service on domain", "在此域名上运行的服务的一些信息"},
		{"Submit", "提交"},
		{"Domain can't end with .b32.i2p", "域名不能以 .b32.i2p 结尾"},
		{"Domain must end with .i2p", "域名必须以 .i2p 结尾"},
		{"Such destination is not found", "找不到此目标"},
		{"Unknown command", "未知指令"},
		{"Command accepted", "已接受指令"},
		{"Proxy error", "代理错误"},
		{"Proxy info", "代理信息"},
		{"Proxy error: Host not found", "代理错误：未找到主机"},
		{"Remote host not found in router's addressbook", "在路由地址簿中未找到远程主机"},
		{"You may try to find this host on jump services below", "您可以尝试在下方的跳转服务中找到该主机"},
		{"Invalid request", "无效请求"},
		{"Proxy unable to parse your request", "代理无法解析您的请求"},
		{"addresshelper is not supported", "不支持地址助手"},
		{"Host", "主机"},
		{"added to router's addressbook from helper", "将此地址从地址助手添加到路由地址簿"},
		{"Click here to proceed:", "点击此处继续:"},
		{"Continue", "继续"},
		{"Addresshelper found", "已找到地址助手"},
		{"already in router's addressbook", "已在路由地址簿中"},
		{"Click here to update record:", "点击此处更新地址簿记录"},
		{"invalid request uri", "无效的 URL 请求"},
		{"Can't detect destination host from request", "无法从请求中检测到目标主机"},
		{"Outproxy failure", "出口代理故障"},
		{"bad outproxy settings", "错误的出口代理设置"},
		{"not inside I2P network, but outproxy is not enabled", "该地址不在 I2P 网络内，但未启用出口代理"},
		{"unknown outproxy url", "未知的出口代理地址"},
		{"cannot resolve upstream proxy", "无法解析上游代理"},
		{"hostname too long", "主机名过长"},
		{"cannot connect to upstream socks proxy", "无法连接到上游 socks 代理"},
		{"Cannot negotiate with socks proxy", "无法与 socks 代理协商"},
		{"CONNECT error", "连接错误"},
		{"Failed to Connect", "连接失败"},
		{"socks proxy error", "socks 代理错误"},
		{"failed to send request to upstream", "向上游发送请求失败"},
		{"No Reply From socks proxy", "没有来自 socks 代理的回复"},
		{"cannot connect", "无法连接"},
		{"http out proxy not implemented", "http 出口代理未实现"},
		{"cannot connect to upstream http proxy", "无法连接到上游 http 代理"},
		{"Host is down", "主机已关闭"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "无法创建到目标主机的连接。主机可能已下线，请稍后再试。"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d 日"}},
		{"%d hours", {"%d 时"}},
		{"%d minutes", {"%d 分"}},
		{"%d seconds", {"%d 秒"}},
		{"", {""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
