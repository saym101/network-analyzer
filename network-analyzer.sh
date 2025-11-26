#!/bin/bash

# Network Analyzer for Debian 12 / Ubuntu 20+
# Комплексный анализ сетевой конфигурации и диагностика
################################################################################

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
# MAGENTA='\033[0;35m' 
BOLD='\033[1m'
NC='\033[0m' # No Color

# Параметры по умолчанию
QUICK_MODE=false
DEEP_MODE=false
WITH_TRAFFIC=false
WITH_PASSWORDS=false
OUTPUT_FORMAT="txt"
OUTPUT_FILE=""
NEED_ROOT=false

################################################################################
# Функция: вывод использования
################################################################################
usage() {
    cat << EOF
Использование: $0 [ОПЦИИ]

Опции:
  --quick              Быстрый режим (основная информация)
  --deep               Глубокий режим (максимум деталей)
  --with-traffic       Показать статистику трафика
  --with-passwords     Включить пароли WiFi (требует root)
  --json [FILE]        Вывод в JSON (опционально в файл)
  --txt [FILE]         Вывод в TXT (опционально в файл)
  -h, --help           Показать эту справку

Примеры:
  $0                           # Стандартный анализ
  $0 --deep --with-traffic     # Полный анализ с трафиком
  $0 --quick                   # Быстрая диагностика
  sudo $0 --with-passwords     # Показать пароли WiFi

EOF
    exit 0
}

################################################################################
# Парсинг аргументов
################################################################################
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick) QUICK_MODE=true; shift ;;
        --deep) DEEP_MODE=true; shift ;;
        --with-traffic) WITH_TRAFFIC=true; shift ;;
        --with-passwords) WITH_PASSWORDS=true; NEED_ROOT=true; shift ;;
        --json)
            OUTPUT_FORMAT="json"
            OUTPUT_FILE=""
            shift
            if [[ $# -gt 0 && "$1" != --* ]]; then
                OUTPUT_FILE="$1"
                shift
            fi
            ;;
        --txt)
            OUTPUT_FORMAT="txt"
            OUTPUT_FILE=""
            shift
            if [[ $# -gt 0 && "$1" != --* ]]; then
                OUTPUT_FILE="$1"
                shift
            fi
            ;;
        -h|--help) usage ;;
        *) echo "Неизвестная опция: $1"; usage ;;
    esac
done

###########################################################################
# Проверка root при необходимости
if [[ "$NEED_ROOT" == true ]] && [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Ошибка: для --with-passwords требуются права root${NC}" >&2
    exit 1
fi

###########################################################################
# Настройка формата вывода и файла отчёта
###########################################################################

# Если запросили JSON, честно предупреждаем, что пока не умеем
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo -e "${YELLOW}Предупреждение:${NC} JSON-вывод пока не реализован. Будет сохранён текстовый отчёт." >&2
    OUTPUT_FORMAT="txt"
fi

# Если формат txt — готовим файл
if [[ "$OUTPUT_FORMAT" == "txt" ]]; then
    # Если файл явно не задан через --txt, создаём рядом со скриптом
    if [[ -z "$OUTPUT_FILE" ]]; then
        SCRIPT_PATH="$(readlink -f "$0")"
        SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
        TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
        OUTPUT_FILE="${SCRIPT_DIR}/network-analyzer-${TIMESTAMP}.txt"
    fi

    # Сообщаем, куда пишем отчёт
    echo -e "${YELLOW}Отчёт будет сохранён в файл: ${OUTPUT_FILE}${NC}" >&2

	# Создаём чистый лог без ANSI-кодов
	# Поток STDOUT → tee → sed → файл
	exec > >(tee >(sed -r "s/\x1B\[[0-9;]*[A-Za-z]//g" > "$OUTPUT_FILE"))
	# STDERR тоже отправляем в STDOUT
	exec 2>&1

fi

################################################################################
# Проверка утилит
################################################################################
REQUIRED_TOOLS="ip ss grep awk sed"
OPTIONAL_TOOLS="ethtool iwconfig nmcli netstat iptables nft tc brctl ovs-vsctl docker tcpdump route iw"

declare -A TOOL_PACKAGE_MAP=(
    [ethtool]="ethtool"
    [iwconfig]="wireless-tools"
    [nmcli]="network-manager"
    [netstat]="net-tools"
    [route]="net-tools"
    [iptables]="iptables"
    [nft]="nftables"
    [tc]="iproute2"
    [brctl]="bridge-utils"
    [ovs-vsctl]="openvswitch-switch"
    [docker]="docker.io"
    [tcpdump]="tcpdump"
    [traceroute]="traceroute"
    [host]="bind9-host"
    [iw]="iw"
    [wg]="wireguard-tools"
    [conntrack]="conntrack"
)

MISSING_REQUIRED=()
MISSING_OPTIONAL=()

echo -e "${CYAN}${BOLD}=== Проверка необходимых утилит ===${NC}\n"

for tool in $REQUIRED_TOOLS; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_REQUIRED+=("$tool")
    fi
done

for tool in $OPTIONAL_TOOLS; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_OPTIONAL+=("$tool")
    fi
done

if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    echo -e "${RED}Отсутствуют обязательные утилиты:${NC} ${MISSING_REQUIRED[*]}"
    echo -e "${YELLOW}Установите их командой:${NC}"
    echo "  apt update && apt install -y iproute2 coreutils"
    exit 1
fi

if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Отсутствуют опциональные утилиты (некоторые функции будут недоступны):${NC}"
    echo "  ${MISSING_OPTIONAL[*]}"
    echo ""
    
    # Собираем уникальные пакеты для установки
    missing_packages=()
    for tool in "${MISSING_OPTIONAL[@]}"; do
        pkg=${TOOL_PACKAGE_MAP[$tool]-}
        [[ -z "$pkg" ]] && continue
		if [[ " ${missing_packages[*]} " != *" ${pkg} "* ]]; then
  		  missing_packages+=("$pkg")
		fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Для расширенного функционала установите:${NC}"
        echo "  apt install -y ${missing_packages[*]}"
        echo ""
    fi
fi

echo -e "${GREEN}✓ Проверка завершена${NC}\n"

################################################################################
# Основные функции
################################################################################

print_header() {
    local title="$1"
    echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $title${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_subheader() {
    local title="$1"
    echo -e "${BLUE}${BOLD}▶ $title${NC}"
}

print_file_content() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]]; then
        echo -e "${YELLOW}$description: $file${NC}"
        cat "$file" 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "  (пусто или недоступно)"
        echo ""
    fi
}

################################################################################
# 1. Системная информация и hostname
################################################################################
show_system_info() {
    print_header "1. Системная информация"
    
    echo -e "${BOLD}Hostname:${NC} $(hostname)"
    echo -e "${BOLD}FQDN:${NC} $(hostname -f 2>/dev/null || echo 'не настроен')"
    echo -e "${BOLD}Domain:${NC} $(hostname -d 2>/dev/null || echo 'не настроен')"
    echo -e "${BOLD}Kernel:${NC} $(uname -r)"
    echo -e "${BOLD}OS:${NC} $(awk -F\" '/^PRETTY_NAME=/ {print $2}' /etc/os-release)"
    echo ""
    
    print_file_content "/etc/hostname" "Файл hostname"
    print_file_content "/etc/hosts" "Файл hosts"
    print_file_content "/etc/resolv.conf" "DNS конфигурация"
    print_file_content "/etc/nsswitch.conf" "Name Service Switch"
}

################################################################################
# 2. Сетевые интерфейсы
################################################################################
show_network_interfaces() {
    print_header "2. Сетевые интерфейсы"
    
    print_subheader "Список интерфейсов"
    ip -br addr show
    echo ""
    
    print_subheader "Детальная информация"
    ip addr show
    echo ""
    
    if command -v ethtool &> /dev/null; then
        print_subheader "Состояние сетевых карт (ethtool)"
        for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
            echo -e "${YELLOW}Интерфейс: $iface${NC}"
            ethtool "$iface" 2>/dev/null | grep -E "(Speed|Duplex|Link detected|Auto-negotiation)" || echo "  Недоступно"
            echo ""
        done
    fi
    
    print_subheader "Статистика интерфейсов"
    ip -s link show
    echo ""
    
    if command -v ifconfig &> /dev/null; then
        print_subheader "ifconfig (legacy)"
        ifconfig -a
        echo ""
    fi
}

################################################################################
# 3. IP адреса и маршрутизация
################################################################################
show_routing() {
    print_header "3. Маршрутизация"
    
    print_subheader "Таблица маршрутизации IPv4"
    ip route show
    echo ""
    
    print_subheader "Таблица маршрутизации IPv6"
    ip -6 route show 2>/dev/null || echo "IPv6 не настроен"
    echo ""
    
    print_subheader "Все таблицы маршрутизации"
    ip route show table all 2>/dev/null | head -50
    echo ""
    
    print_subheader "Правила маршрутизации (Policy Routing)"
    ip rule show
    echo ""
    
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward)
        echo -e "${BOLD}IPv4 Forwarding:${NC} $([ "$ipv4_forward" = "1" ] && echo "${GREEN}ВКЛЮЧЕН${NC}" || echo "${RED}ВЫКЛЮЧЕН${NC}")"
    fi
    
    if [[ -f /proc/sys/net/ipv6/conf/all/forwarding ]]; then
        ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
        echo -e "${BOLD}IPv6 Forwarding:${NC} $([ "$ipv6_forward" = "1" ] && echo "${GREEN}ВКЛЮЧЕН${NC}" || echo "${RED}ВЫКЛЮЧЕН${NC}")"
    fi
    echo ""
}

################################################################################
# 4. ARP и Neighbor таблицы
################################################################################
show_arp_neighbors() {
    print_header "4. ARP / Neighbor таблицы"
    
    print_subheader "ARP кеш (IPv4)"
    ip neigh show
    echo ""
    
    if command -v arp &> /dev/null; then
        print_subheader "arp -a (legacy)"
        arp -a
        echo ""
    fi
}

################################################################################
# 5. DNS
################################################################################
show_dns() {
    print_header "5. DNS конфигурация"
    
    print_file_content "/etc/resolv.conf" "Текущие DNS серверы"
    print_file_content "/run/systemd/resolve/resolv.conf" "systemd-resolved (dynamic)"
    print_file_content "/run/systemd/resolve/stub-resolv.conf" "systemd-resolved (stub)"
    
    if command -v systemd-resolve &> /dev/null; then
        print_subheader "systemd-resolved статус"
        systemd-resolve --status 2>/dev/null || systemctl status systemd-resolved --no-pager
        echo ""
    fi
    
    if command -v resolvectl &> /dev/null; then
        print_subheader "resolvectl status"
        resolvectl status 2>/dev/null || true
        echo ""
    fi
    
    print_subheader "Тест DNS разрешения"
    for domain in google.com cloudflare.com; do
        echo -n "  $domain: "
        host "$domain" 2>/dev/null | head -1 || echo "Ошибка"
    done
    echo ""
}

################################################################################
# 6. Активные соединения
################################################################################
show_connections() {
    print_header "6. Активные соединения"
    
    print_subheader "Слушающие порты (ss)"
    ss -tulpn 2>/dev/null | head -50 || ss -tuln | head -50
    echo ""
    
    print_subheader "Установленные соединения (top 20)"
    ss -tunp state established 2>/dev/null | head -20 || ss -tun state established | head -20
    echo ""
    
    if command -v netstat &> /dev/null; then
        print_subheader "netstat -tunlp (legacy)"
        netstat -tunlp 2>/dev/null | head -30 || netstat -tunl | head -30
        echo ""
    fi
    
    print_subheader "Количество соединений по состояниям"
    ss -tan | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn
    echo ""
}

################################################################################
# 7. Firewall (iptables / nftables)
################################################################################
show_firewall() {
    print_header "7. Firewall конфигурация"
    
    # iptables
    if command -v iptables &> /dev/null; then
        print_subheader "iptables - Filter таблица"
        iptables -L -n -v 2>/dev/null || echo "Требуются права root"
        echo ""
        
        print_subheader "iptables - NAT таблица"
        iptables -t nat -L -n -v 2>/dev/null || echo "Требуются права root"
        echo ""
        
        print_subheader "iptables - Mangle таблица"
        iptables -t mangle -L -n -v 2>/dev/null || echo "Требуются права root"
        echo ""
    fi
    
    # nftables
    if command -v nft &> /dev/null; then
        print_subheader "nftables конфигурация"
        nft list ruleset 2>/dev/null || echo "Требуются права root или nftables не используется"
        echo ""
    fi
    
    # ufw
    if command -v ufw &> /dev/null; then
        print_subheader "UFW (Uncomplicated Firewall)"
        ufw status verbose 2>/dev/null || echo "Требуются права root"
        echo ""
    fi
    
    # firewalld
    if command -v firewall-cmd &> /dev/null; then
        print_subheader "firewalld"
        firewall-cmd --list-all 2>/dev/null || echo "firewalld не запущен или требуются права"
        echo ""
    fi
}

################################################################################
# 8. NAT и проброс портов
################################################################################
show_nat() {
    print_header "8. NAT и Port Forwarding"
    
    print_subheader "SNAT / MASQUERADE правила"
    iptables -t nat -L POSTROUTING -n -v 2>/dev/null || echo "Требуются права root"
    echo ""
    
    print_subheader "DNAT / Port Forwarding правила"
    iptables -t nat -L PREROUTING -n -v 2>/dev/null || echo "Требуются права root"
    echo ""
    
    print_subheader "Conntrack (отслеживание соединений)"
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        echo "  Текущие соединения: $count / $max"
    fi
    
    if command -v conntrack &> /dev/null; then
        echo ""
        echo "  Топ-10 conntrack записей:"
        conntrack -L 2>/dev/null | head -10 || echo "  Требуются права root"
    fi
    echo ""
}

################################################################################
# 9. Wireless (WiFi)
################################################################################
show_wireless() {
    print_header "9. Беспроводные сети (WiFi)"

    # Если нет iw - честно пишем и выходим из блока
    if ! command -v iw &> /dev/null; then
        echo "Утилита iw не установлена, пропускаю WiFi-анализ"
        echo ""
        return
    fi
    
    # Проверяем наличие WiFi интерфейсов
    wifi_interfaces=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    if [[ -z "${wifi_interfaces:-}" ]]; then
        echo "WiFi интерфейсы не обнаружены"
        echo ""
        return
    fi

    if command -v iw &> /dev/null; then
        print_subheader "Информация о WiFi интерфейсах"
        iw dev 2>/dev/null || echo "iw не смог получить информацию"
        echo ""
    fi

    if command -v iwconfig &> /dev/null; then
        print_subheader "iwconfig"
        iwconfig 2>/dev/null | grep -v "no wireless"
        echo ""
    fi

    if command -v nmcli &> /dev/null; then
        print_subheader "NetworkManager - WiFi соединения"
        nmcli device wifi list 2>/dev/null || echo "NetworkManager не запущен"
        echo ""
        
        if [[ "$WITH_PASSWORDS" == true ]]; then
            print_subheader "Сохраненные WiFi пароли"
            nmcli -s -g name,802-11-wireless-security.psk connection show 2>/dev/null || echo "Требуются права root"
            echo ""
        fi
    fi

    # Сканирование доступных сетей (по желанию оставить как есть)
    if [[ $EUID -eq 0 ]]; then
        print_subheader "Доступные WiFi сети"
        for iface in $wifi_interfaces; do
            echo -e "${YELLOW}Интерфейс: $iface${NC}"
            iw dev "$iface" scan 2>/dev/null | grep -E "(SSID|signal|freq)" | head -30 || echo "Требуются права root или сканирование недоступно"
        done
        echo ""
    fi
}


################################################################################
# 10. VPN конфигурации
################################################################################
show_vpn() {
    print_header "10. VPN конфигурации"
    
    # OpenVPN
    if command -v openvpn &> /dev/null; then
        print_subheader "OpenVPN"
        systemctl status openvpn@* --no-pager 2>/dev/null || echo "OpenVPN не настроен"
        echo ""
        
        if [[ -d /etc/openvpn ]]; then
            echo "Конфигурационные файлы:"
            ls -lh /etc/openvpn/*.conf 2>/dev/null || echo "  Конфигурации не найдены"
            echo ""
        fi
    fi
    
    # WireGuard
    if command -v wg &> /dev/null; then
        print_subheader "WireGuard"
        wg show 2>/dev/null || echo "WireGuard не настроен или требуются права root"
        echo ""
    fi
    
    # IPsec (strongSwan / libreswan)
    if command -v ipsec &> /dev/null; then
        print_subheader "IPsec"
        ipsec status 2>/dev/null || echo "IPsec не запущен"
        echo ""
    fi
    
    # PPTP
    if [[ -f /etc/ppp/options.pptp ]]; then
        print_file_content "/etc/ppp/options.pptp" "PPTP конфигурация"
    fi
}

################################################################################
# 11. Мосты и VLAN
################################################################################
show_bridges_vlans() {
    print_header "11. Мосты и VLAN"
    
    print_subheader "Linux Bridge"
    ip link show type bridge 2>/dev/null || echo "Мосты не найдены"
    echo ""
    
    if command -v brctl &> /dev/null; then
        print_subheader "brctl show"
        brctl show 2>/dev/null || echo "bridge-utils не установлен"
        echo ""
    fi
    
    print_subheader "VLAN интерфейсы"
    ip -d link show type vlan 2>/dev/null || echo "VLAN интерфейсы не найдены"
    echo ""
    
    # Open vSwitch
    if command -v ovs-vsctl &> /dev/null; then
        print_subheader "Open vSwitch"
        ovs-vsctl show 2>/dev/null || echo "OVS не настроен"
        echo ""
    fi
}

################################################################################
# 12. Bonding / Teaming
################################################################################
show_bonding() {
    print_header "12. Bonding / Link Aggregation"
    
    if [[ -d /proc/net/bonding ]]; then
        print_subheader "Bonding интерфейсы"
        for bond in /proc/net/bonding/*; do
            if [[ -f "$bond" ]]; then
                echo -e "${YELLOW}$(basename "$bond"):${NC}"
                cat "$bond"
                echo ""
            fi
        done
    else
        echo "Bonding не настроен"
        echo ""
    fi
    
    # Team
    if command -v teamdctl &> /dev/null; then
        print_subheader "Team интерфейсы"
        teamdctl team0 state 2>/dev/null || echo "Team не настроен"
        echo ""
    fi
}

################################################################################
# 13. QoS и Traffic Control
################################################################################
show_qos() {
    print_header "13. QoS / Traffic Control"
    
    if command -v tc &> /dev/null; then
        print_subheader "Traffic Control (tc) правила"
        for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
            qdisc=$(tc qdisc show dev "$iface" 2>/dev/null)
            if [[ "$qdisc" != *"noqueue"* ]] && [[ -n "$qdisc" ]]; then
                echo -e "${YELLOW}Интерфейс: $iface${NC}"
                tc qdisc show dev "$iface"
                tc class show dev "$iface" 2>/dev/null
                tc filter show dev "$iface" 2>/dev/null
                echo ""
            fi
        done
    else
        echo "tc (iproute2) не установлен"
    fi
    echo ""
}

################################################################################
# 14. Proxy настройки
################################################################################
show_proxy() {
    print_header "14. Proxy конфигурация"
    
    print_subheader "Системные переменные proxy"
    env | grep -i proxy || echo "Системный proxy не настроен"
    echo ""
    
    print_file_content "/etc/environment" "Глобальный /etc/environment"
    print_file_content "/etc/apt/apt.conf" "APT proxy"
    print_file_content "/etc/apt/apt.conf.d/95proxies" "APT proxy (95proxies)"
    
    # Squid
    if command -v squid &> /dev/null; then
        print_subheader "Squid proxy"
        systemctl status squid --no-pager 2>/dev/null || echo "Squid не запущен"
        echo ""
        
        if [[ -f /etc/squid/squid.conf ]]; then
            echo "Squid конфигурация (основные директивы):"
            grep -v "^#" /etc/squid/squid.conf | grep -v "^$" | head -30
            echo ""
        fi
    fi
    
    # SOCKS proxy
    if ss -tlnp 2>/dev/null | grep -q ":1080"; then
        echo -e "${YELLOW}SOCKS proxy обнаружен на порту 1080${NC}"
        ss -tlnp 2>/dev/null | grep ":1080"
        echo ""
    fi
}

################################################################################
# 15. DHCP
################################################################################
show_dhcp() {
    print_header "15. DHCP конфигурация"
    
    # DHCP Client
    print_subheader "DHCP Client лизы"
    if [[ -d /var/lib/dhcp ]]; then
        ls -lh /var/lib/dhcp/
        echo ""
        for lease in /var/lib/dhcp/dhclient*.leases; do
            if [[ -f "$lease" ]]; then
                echo -e "${YELLOW}$lease:${NC}"
                tail -20 "$lease"
                echo ""
            fi
        done
    fi
    
    # DHCP Server
    if command -v dhcpd &> /dev/null; then
        print_subheader "DHCP Server (isc-dhcp-server)"
        systemctl status isc-dhcp-server --no-pager 2>/dev/null || echo "DHCP сервер не запущен"
        echo ""
        
        print_file_content "/etc/dhcp/dhcpd.conf" "DHCP Server конфигурация"
    fi
    
    # dnsmasq
    if command -v dnsmasq &> /dev/null; then
        print_subheader "dnsmasq (DHCP + DNS)"
        systemctl status dnsmasq --no-pager 2>/dev/null || echo "dnsmasq не запущен"
        echo ""
        
        print_file_content "/etc/dnsmasq.conf" "dnsmasq конфигурация"
    fi
}

################################################################################
# 16. NetworkManager
################################################################################
show_networkmanager() {
    print_header "16. NetworkManager"
    
    if ! command -v nmcli &> /dev/null; then
        echo "NetworkManager не установлен"
        echo ""
        return
    fi
    
    print_subheader "Статус NetworkManager"
    nmcli general status
    echo ""
    
    print_subheader "Все подключения"
    nmcli connection show
    echo ""
    
    print_subheader "Активные подключения"
    nmcli connection show --active
    echo ""
    
    print_subheader "Устройства"
    nmcli device status
    echo ""
    
    # Конфигурационные файлы
    if [[ -d /etc/NetworkManager/system-connections ]]; then
        print_subheader "Сохраненные подключения"
        ls -lh /etc/NetworkManager/system-connections/
        echo ""
    fi
}

################################################################################
# 17. Netplan / systemd-networkd
################################################################################
show_netplan_systemd() {
    print_header "17. Netplan / systemd-networkd"
    
    # Netplan
    if command -v netplan &> /dev/null; then
        print_subheader "Netplan конфигурация"
        
        if [[ -d /etc/netplan ]]; then
            for conf in /etc/netplan/*.yaml; do
                if [[ -f "$conf" ]]; then
                    echo -e "${YELLOW}$conf:${NC}"
                    cat "$conf"
                    echo ""
                fi
            done
        fi
        
        netplan get 2>/dev/null || true
        echo ""
    fi
    
    # systemd-networkd
    if systemctl is-active --quiet systemd-networkd; then
        print_subheader "systemd-networkd"
        systemctl status systemd-networkd --no-pager
        echo ""
        
        if [[ -d /etc/systemd/network ]]; then
            echo "Конфигурационные файлы:"
            ls -lh /etc/systemd/network/
            echo ""
            
            for conf in /etc/systemd/network/*.network; do
                if [[ -f "$conf" ]]; then
                    echo -e "${YELLOW}$conf:${NC}"
                    cat "$conf"
                    echo ""
                fi
            done
        fi
    fi
}

################################################################################
# 18. Docker сети
################################################################################
show_docker_network() {
    print_header "18. Docker сети"
    
    if ! command -v docker &> /dev/null; then
        echo "Docker не установлен"
        echo ""
        return
    fi
    
    if ! docker info &> /dev/null; then
        echo "Docker не запущен или требуются права"
        echo ""
        return
    fi
    
    print_subheader "Docker сети"
    docker network ls 2>/dev/null || { echo "Требуются права для docker network ls"; echo ""; return; }
    echo ""
    
    print_subheader "Детальная информация о сетях"
    for network in $(docker network ls -q 2>/dev/null); do
        # Аккуратно вытаскиваем имя через awk, не издеваясь над кавычками
        net_name=$(docker network inspect "$network" 2>/dev/null | awk -F\" '/"Name"/ {print $4; exit}')
        [[ -z "${net_name:-}" ]] && net_name="$network"

        echo -e "${YELLOW}Сеть: ${net_name}${NC}"
        docker network inspect "$network" 2>/dev/null | grep -E "(Subnet|Gateway|Driver)" | head -5 || echo "  Нет данных по сети"
        echo ""
    done
}


################################################################################
# 19. Статистика трафика
################################################################################
show_traffic_stats() {
    if [[ "$WITH_TRAFFIC" != true ]]; then
        return
    fi
    
    print_header "19. Статистика трафика"
    
    print_subheader "Трафик по интерфейсам (RX/TX)"
    ip -s link show
    echo ""
    
    if command -v iftop &> /dev/null; then
        print_subheader "Топ соединений (iftop - требует время)"
        echo "Для интерактивного просмотра запустите: sudo iftop"
        echo ""
    fi
    
    if command -v vnstat &> /dev/null; then
        print_subheader "vnstat статистика"
        vnstat 2>/dev/null || echo "vnstat не настроен"
        echo ""
    fi
}

################################################################################
# 20. Сетевые сервисы
################################################################################
show_network_services() {
    print_header "20. Сетевые сервисы"
    
    print_subheader "HTTP/HTTPS серверы"
    ss -tlnp 2>/dev/null | grep -E ":(80|443|8080|8443)" || echo "Веб-серверы не обнаружены"
    echo ""
    
    # Nginx
    if command -v nginx &> /dev/null; then
        echo -e "${YELLOW}Nginx:${NC}"
        systemctl status nginx --no-pager 2>/dev/null || echo "  Не запущен"
        nginx -v 2>&1
        echo ""
    fi
    
    # Apache
    if command -v apache2 &> /dev/null; then
        echo -e "${YELLOW}Apache:${NC}"
        systemctl status apache2 --no-pager 2>/dev/null || echo "  Не запущен"
        apache2 -v 2>&1 | head -1
        echo ""
    fi
    
    print_subheader "Mail серверы (SMTP/IMAP/POP3)"
    ss -tlnp 2>/dev/null | grep -E ":(25|465|587|993|995|143|110)" || echo "Mail серверы не обнаружены"
    echo ""
    
    print_subheader "Database серверы"
    ss -tlnp 2>/dev/null | grep -E ":(3306|5432|27017|6379)" || echo "Database серверы не обнаружены"
    echo ""
    
    print_subheader "SSH серверы"
    ss -tlnp 2>/dev/null | grep ":22" || echo "SSH не слушает"
    echo ""
}

################################################################################
# 21. Сетевая безопасность
################################################################################
show_security() {
    print_header "21. Сетевая безопасность"
    
    print_subheader "TCP Wrappers"
    print_file_content "/etc/hosts.allow" "hosts.allow (разрешено)"
    print_file_content "/etc/hosts.deny" "hosts.deny (запрещено)"
    
   print_subheader "Параметры ядра (sysctl network)"
	sysctl -a 2>/dev/null \
    | grep -E "net\.(ipv4|ipv6)" \
    | grep -E "(forward|redirect|accept)" \
    | head -30 \
    || true
	echo ""
    
    print_file_content "/etc/sysctl.conf" "Постоянные настройки sysctl"
    
    if [[ -d /etc/sysctl.d ]]; then
        echo -e "${YELLOW}Дополнительные файлы sysctl.d:${NC}"
        ls -lh /etc/sysctl.d/*.conf 2>/dev/null || echo "  Не найдены"
        echo ""
    fi
    
    print_subheader "fail2ban"
    if command -v fail2ban-client &> /dev/null; then
        systemctl status fail2ban --no-pager 2>/dev/null || echo "fail2ban не запущен"
        fail2ban-client status 2>/dev/null || echo "Требуются права root"
        echo ""
    else
        echo "fail2ban не установлен"
        echo ""
    fi
}

################################################################################
# 22. IPv6 конфигурация
################################################################################
show_ipv6() {
    print_header "22. IPv6 конфигурация"

    # Проверка, поддерживается ли вообще IPv6 в системе
    if ! ip -6 addr show &>/dev/null; then
        echo "IPv6 не поддерживается или отключен (ip -6 addr вернул ошибку)"
        echo ""
        return 0
    fi

    print_subheader "IPv6 адреса"
    ip -6 addr show
    echo ""

    print_subheader "IPv6 маршруты"
    ip -6 route show 2>/dev/null || echo "Маршруты IPv6 не настроены или недоступны"
    echo ""

    print_subheader "IPv6 neighbor"
    ip -6 neigh show 2>/dev/null || echo "Neighbor-таблица IPv6 недоступна"
    echo ""

    print_subheader "IPv6 параметры ядра"
    sysctl -a 2>/dev/null | grep "net.ipv6" | head -20 || echo "Параметры net.ipv6 не найдены"
    echo ""
}

################################################################################
# 23. Туннели
################################################################################
show_tunnels() {
    print_header "23. Туннели (GRE, IPIP, SIT)"
    
    print_subheader "GRE туннели"
    ip tunnel show 2>/dev/null | grep gre || echo "GRE туннели не найдены"
    echo ""
    
    print_subheader "IPIP туннели"
    ip tunnel show 2>/dev/null | grep ipip || echo "IPIP туннели не найдены"
    echo ""
    
    print_subheader "SIT туннели (6in4)"
    ip tunnel show 2>/dev/null | grep sit || echo "SIT туннели не найдены"
    echo ""
    
    print_subheader "Все туннели"
    ip link show type gre 2>/dev/null
    ip link show type ipip 2>/dev/null
    ip link show type sit 2>/dev/null
    echo ""
}

################################################################################
# 24. Мультикаст
################################################################################
show_multicast() {
    print_header "24. Multicast"
    
    print_subheader "Multicast маршруты"
    ip mroute show 2>/dev/null || echo "Multicast routing не включен"
    echo ""
    
    print_subheader "Multicast группы"
    ip maddr show 2>/dev/null
    echo ""
    
    if [[ -f /proc/net/igmp ]]; then
        print_subheader "IGMP (IPv4 multicast)"
        cat /proc/net/igmp
        echo ""
    fi
}

################################################################################
# 25. Диагностические тесты
################################################################################
show_diagnostics() {
    print_header "25. Диагностика подключения"
    
    print_subheader "Тест локального loopback"
    ping -c 2 127.0.0.1 &> /dev/null && echo "  ✓ Loopback работает" || echo "  ✗ Loopback не работает"
    echo ""
    
    print_subheader "Тест шлюза по умолчанию"
    gateway=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$gateway" ]]; then
        echo "  Шлюз: $gateway"
        ping -c 2 -W 2 "$gateway" &> /dev/null && echo "  ✓ Шлюз доступен" || echo "  ✗ Шлюз недоступен"
    else
        echo "  Шлюз по умолчанию не настроен"
    fi
    echo ""
    
    print_subheader "Тест DNS разрешения"
    for domain in google.com 8.8.8.8; do
        echo -n "  $domain: "
        ping -c 1 -W 2 "$domain" &> /dev/null && echo "✓ Доступен" || echo "✗ Недоступен"
    done
    echo ""
    
    print_subheader "Traceroute к внешнему хосту"
    if command -v traceroute &> /dev/null; then
        echo "  traceroute 8.8.8.8 (первые 5 хопов):"
        traceroute -m 5 -w 2 8.8.8.8 2>/dev/null | tail -5 || echo "  Недоступно"
    else
        echo "  traceroute не установлен"
    fi
    echo ""
}

################################################################################
# 26. Логи и журналы
################################################################################
show_logs() {
    print_header "26. Сетевые логи"
    
    print_subheader "Последние сетевые события (journalctl)"
    journalctl -u NetworkManager -u systemd-networkd -u networking --no-pager -n 20 2>/dev/null || echo "Требуются права или журналы недоступны"
    echo ""
    
    print_subheader "Kernel сетевые сообщения"
    dmesg | grep -E "(eth|wlan|link|network)" | tail -20 || echo "Требуются права"
    echo ""
    
    if [[ -f /var/log/syslog ]]; then
        print_subheader "Последние сетевые записи в syslog"
        grep -E "(DHCP|NetworkManager|network)" /var/log/syslog 2>/dev/null | tail -20 || echo "Требуются права"
        echo ""
    fi
}

################################################################################
# 27. Производительность сети
################################################################################
show_performance() {
    print_header "27. Производительность сети"
    
    print_subheader "Параметры TCP буферов"
    sysctl net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem 2>/dev/null
    echo ""
    
    print_subheader "TCP параметры"
    sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_window_scaling net.ipv4.tcp_timestamps 2>/dev/null
    echo ""
    
    print_subheader "Сетевые очереди"
    sysctl net.core.netdev_max_backlog net.core.somaxconn 2>/dev/null
    echo ""
    
    if [[ -f /proc/net/softnet_stat ]]; then
        print_subheader "Softnet статистика"
        cat /proc/net/softnet_stat | head -5
        echo ""
    fi
}




################################################################################
# MAIN
################################################################################

# Если вывод идёт в файл — clear не нужен
if [[ -z "$OUTPUT_FILE" ]]; then
    clear
fi

echo -e "${BOLD}${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║         NETWORK ANALYZER — Анализ сетевой конфигурации            ║
║                   Debian 12 / Ubuntu 20+                          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "Запуск анализа: ${BOLD}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "Режим: ${BOLD}$([[ "$QUICK_MODE" == true ]] && echo "БЫСТРЫЙ" || [[ "$DEEP_MODE" == true ]] && echo "ГЛУБОКИЙ" || echo "СТАНДАРТНЫЙ")${NC}"
echo ""

# Запуск всех проверок
show_system_info
show_network_interfaces
show_routing
show_arp_neighbors
show_dns

if [[ "$QUICK_MODE" != true ]]; then
    show_connections
    show_firewall
    show_nat
    show_wireless
    show_vpn
    show_bridges_vlans
    show_bonding
    show_qos
    show_proxy
    show_dhcp
    show_networkmanager
    show_netplan_systemd
    show_docker_network
    show_traffic_stats
    show_network_services
    show_security
    show_ipv6
    show_tunnels
    show_multicast
    show_diagnostics
    show_logs
    show_performance
fi

print_header "ИТОГИ"

echo -e "${BOLD}Режим работы сети:${NC}"

# Определение режима
is_router=false
is_proxy=false
has_nat=false
has_firewall=false

if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward)
    if [[ "$ipv4_forward" == "1" ]]; then
        is_router=true
        echo "  • ${GREEN}Маршрутизатор/Router (IP forwarding включен)${NC}"
    fi
fi

if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
    has_nat=true
    echo "  • ${GREEN}NAT/MASQUERADE настроен${NC}"
fi

if iptables -L -n 2>/dev/null | grep -qE "(REJECT|DROP)" || nft list ruleset 2>/dev/null | grep -q "drop"; then
    has_firewall=true
    echo "  • ${GREEN}Firewall активен${NC}"
fi

if env | grep -qi proxy || [[ -f /etc/squid/squid.conf ]]; then
    is_proxy=true
    echo "  • ${YELLOW}Proxy настроен${NC}"
fi

if ! $is_router && ! $is_proxy && ! $has_nat && ! $has_firewall; then
    echo "  • ${BLUE}Обычная рабочая станция / клиент${NC}"
fi


echo ""
echo -e "${BOLD}Активные сетевые интерфейсы:${NC}"
ip -br addr show | grep -v "DOWN" | while read -r line; do
    echo "  • $line"
done

echo ""
echo -e "${GREEN}${BOLD}✓ Анализ завершен: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

exit 0

