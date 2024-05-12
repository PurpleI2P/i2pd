/*
* Copyright (c) 2023-2024, The PurpleI2P Project
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

// Portuguese localization file

namespace i2p
{
namespace i18n
{
namespace portuguese // language namespace
{
	// language name in lowercase
	static std::string language = "portuguese";

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
		{"building", "construindo"},
		{"failed", "falhou"},
		{"expiring", "expirando"},
		{"established", "estabelecido"},
		{"unknown", "desconhecido"},
		{"exploratory", "exploratório"},
		{"Purple I2P Webconsole", "Webconsole Purple I2P"},
		{"<b>i2pd</b> webconsole", "webconsole <b>i2pd</b>"},
		{"Main page", "Página Principal"},
		{"Router commands", "Comandos do Roteador"},
		{"Local Destinations", "Destinos Locais"},
		{"LeaseSets", "LeaseSets"},
		{"Tunnels", "Túneis"},
		{"Transit Tunnels", "Túneis de Trânsito"},
		{"Transports", "Transportes"},
		{"I2P tunnels", "Túneis I2P"},
		{"SAM sessions", "Sessões do SAM"},
		{"ERROR", "ERRO"},
		{"OK", "OK"},
		{"Testing", "Testando"},
		{"Firewalled", "Sob Firewall"},
		{"Unknown", "Desconhecido"},
		{"Proxy", "Proxy"},
		{"Mesh", "Malha"},
		{"Clock skew", "Desvio de Relógio"},
		{"Offline", "Desligado"},
		{"Symmetric NAT", "NAT Simétrico"},
		{"Full cone NAT", "Full cone NAT"},
		{"No Descriptors", "Sem Descritores"},
		{"Uptime", "Tempo Ativo"},
		{"Network status", "Estado da rede"},
		{"Network status v6", "Estado da rede v6"},
		{"Stopping in", "Parando em"},
		{"Family", "Família"},
		{"Tunnel creation success rate", "Taxa de sucesso na criação de túneis"},
		{"Total tunnel creation success rate", "Taxa total de sucesso na criação de túneis"},
		{"Received", "Recebido"},
		{"%.2f KiB/s", "%.2f KiB/s"},
		{"Sent", "Enviado"},
		{"Transit", "Trânsito"},
		{"Data path", "Diretório de dados"},
		{"Hidden content. Press on text to see.", "Conteúdo oculto. Clique no texto para revelar."},
		{"Router Ident", "Identidade do Roteador"},
		{"Router Family", "Família do Roteador"},
		{"Router Caps", "Limites do Roteador"},
		{"Version", "Versão"},
		{"Our external address", "Nosso endereço externo"},
		{"supported", "suportado"},
		{"Routers", "Roteadores"},
		{"Floodfills", "Modo Inundação"},
		{"Client Tunnels", "Túneis de Clientes"},
		{"Services", "Serviços"},
		{"Enabled", "Ativado"},
		{"Disabled", "Desativado"},
		{"Encrypted B33 address", "Endereço B33 criptografado"},
		{"Address registration line", "Linha de cadastro de endereço"},
		{"Domain", "Domínio"},
		{"Generate", "Gerar"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b> Nota: </b>A string resultante só pode ser usada para registrar domínios 2LD (exemplo.i2p). Para registrar subdomínios por favor utilize o i2pd-tools."},
		{"Address", "Endereço"},
		{"Type", "Tipo"},
		{"EncType", "Tipo de Criptografia"},
		{"Expire LeaseSet", "Expirar LeaseSet"},
		{"Inbound tunnels", "Túneis de Entrada"},
		{"%dms", "%dms"},
		{"Outbound tunnels", "Túneis de Saída"},
		{"Tags", "Etiquetas"},
		{"Incoming", "Entradas"},
		{"Outgoing", "Saídas"},
		{"Destination", "Destinos"},
		{"Amount", "Quantidade"},
		{"Incoming Tags", "Etiquetas de Entrada"},
		{"Tags sessions", "Sessões de Etiquetas"},
		{"Status", "Estado"},
		{"Local Destination", "Destino Local"},
		{"Streams", "Fluxos"},
		{"Close stream", "Fechar fluxo"},
		{"Such destination is not found", "Tal destino não foi encontrado"},
		{"I2CP session not found", "Sessão do I2CP não encontrada"},
		{"I2CP is not enabled", "I2CP não está ativado"},
		{"Invalid", "Inválido"},
		{"Store type", "Tipo de armazenamento"},
		{"Expires", "Expira em"},
		{"Non Expired Leases", "Sessões não expiradas"},
		{"Gateway", "Gateway"},
		{"TunnelID", "TunnelID"},
		{"EndDate", "Data final"},
		{"floodfill mode is disabled", "Mode de inundação está desativado"},
		{"Queue size", "Tamanho da fila"},
		{"Run peer test", "Executar teste de peers"},
		{"Reload tunnels configuration", "Recarregar a configuração dos túneis"},
		{"Decline transit tunnels", "Negar túneis de trânsito"},
		{"Accept transit tunnels", "Aceitar túneis de trânsito"},
		{"Cancel graceful shutdown", "Cancelar desligamento gracioso"},
		{"Start graceful shutdown", "Iniciar desligamento gracioso"},
		{"Force shutdown", "Forçar desligamento"},
		{"Reload external CSS styles", "Recarregar estilos CSS externos"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b> Nota: </b> Qualquer ação feita aqui não será permanente e não altera os seus arquivos de configuração."},
		{"Logging level", "Nível de registro"},
		{"Transit tunnels limit", "Limite de túneis de trânsito"},
		{"Change", "Mudar"},
		{"Change language", "Trocar idioma"},
		{"no transit tunnels currently built", "Nenhum túnel de trânsito construido no momento"},
		{"SAM disabled", "SAM desativado"},
		{"no sessions currently running", "Nenhuma sessão funcionando no momento"},
		{"SAM session not found", "Nenhuma sessão do SAM encontrada"},
		{"SAM Session", "Sessão do SAM"},
		{"Server Tunnels", "Túneis de Servidor"},
		{"Client Forwards", "Túneis de Cliente"},
		{"Server Forwards", "Encaminhamentos de Servidor"},
		{"Unknown page", "Página desconhecida"},
		{"Invalid token", "Token Inválido"},
		{"SUCCESS", "SUCESSO"},
		{"Stream closed", "Fluxo fechado"},
		{"Stream not found or already was closed", "Fluxo não encontrado ou já fechado"},
		{"Destination not found", "Destino não encontrado"},
		{"StreamID can't be null", "StreamID não pode ser nulo"},
		{"Return to destination page", "Retornar para à página de destino"},
		{"You will be redirected in %d seconds", "Você será redirecionado em %d segundos"},
		{"LeaseSet expiration time updated", "Tempo de validade do LeaseSet atualizado"},
		{"LeaseSet is not found or already expired", "LeaseSet não foi encontrado ou já expirou"},
		{"Transit tunnels count must not exceed %d", "A contagem de túneis de trânsito não deve exceder %d"},
		{"Back to commands list", "Voltar para a lista de comandos"},
		{"Register at reg.i2p", "Registrar em reg.i2p"},
		{"Description", "Descrição"},
		{"A bit information about service on domain", "Algumas informações sobre o serviço no domínio"},
		{"Submit", "Enviar"},
		{"Domain can't end with .b32.i2p", "O domínio não pode terminar com .b32.i2p"},
		{"Domain must end with .i2p", "O domínio não pode terminar com .i2p"},
		{"Unknown command", "Comando desconhecido"},
		{"Command accepted", "Comando aceito"},
		{"Proxy error", "Erro no proxy"},
		{"Proxy info", "Informações do proxy"},
		{"Proxy error: Host not found", "Erro no proxy: Host não encontrado"},
		{"Remote host not found in router's addressbook", "O host remoto não foi encontrado no livro de endereços do roteador"},
		{"You may try to find this host on jump services below", "Você pode tentar encontrar este host nos serviços de jump abaixo"},
		{"Invalid request", "Requisição inválida"},
		{"Proxy unable to parse your request", "O proxy foi incapaz de processar a sua requisição"},
		{"Addresshelper is not supported", "O Auxiliar de Endereços não é suportado"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "O host %s já <font color=red>está no catálogo de endereços do roteador</font>. <b>Cuidado: a fonte desta URL pode ser perigosa!</b> Clique aqui para atualizar o registro: <a href=\"%s%s%s&update=true\">Continuar</a>."},
		{"Addresshelper forced update rejected", "A atualização forçada do Auxiliar de Endereços foi rejeitada"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Para adicionar o host <b> %s </b> ao catálogo de endereços do roteador, clique aqui: <a href='%s%s%s'>Continuar </a>."},
		{"Addresshelper request", "Requisição ao Auxiliar de Endereços"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "O host %s foi adicionado ao catálogo de endereços do roteador por um auxiliar. Clique aqui para prosseguir: <a href='%s'> Continuar </a>."},
		{"Addresshelper adding", "Auxiliar de Endereço adicionando"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "O host %s já <font color=red>está no catálogo de endereços do roteador </font>. Clique aqui para atualizar o registro: <a href=\"%s%s%s&update=true\">Continuar</a>."},
		{"Addresshelper update", "Atualização do Auxiliar de Endereços"},
		{"Invalid request URI", "A URI de requisição é inválida"},
		{"Can't detect destination host from request", "Incapaz de detectar o host de destino da requisição"},
		{"Outproxy failure", "Falha no outproxy"},
		{"Bad outproxy settings", "Má configurações do outproxy"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "O host %s não está dentro da rede I2P, mas o outproxy não está ativado"},
		{"Unknown outproxy URL", "URL de outproxy desconhecida"},
		{"Cannot resolve upstream proxy", "Não é possível resolver o proxy de entrada"},
		{"Hostname is too long", "O hostname é muito longo"},
		{"Cannot connect to upstream SOCKS proxy", "Não é possível se conectar ao proxy SOCKS de entrada"},
		{"Cannot negotiate with SOCKS proxy", "Não é possível negociar com o proxy SOCKS"},
		{"CONNECT error", "Erro de CONEXÃO"},
		{"Failed to connect", "Falha ao conectar"},
		{"SOCKS proxy error", "Erro no proxy SOCKS"},
		{"Failed to send request to upstream", "Falha ao enviar requisição para o fluxo de entrada"},
		{"No reply from SOCKS proxy", "Sem resposta do proxy SOCKS"},
		{"Cannot connect", "Impossível conectar"},
		{"HTTP out proxy not implemented", "proxy de saída HTTP não implementado"},
		{"Cannot connect to upstream HTTP proxy", "Não é possível conectar ao proxy HTTP de entrada"},
		{"Host is down", "Host está desligado"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "Não é possível se conectar ao host requisitado, talvez ele esteja for do ar. Por favor, tente novamente mais tarde."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d Dia", "%d Dias"}},
		{"%d hours", {"%d hora", "%d horas"}},
		{"%d minutes", {"%d minuto", "%d minutos"}},
		{"%d seconds", {"%d Segundo", "%d segundos"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
