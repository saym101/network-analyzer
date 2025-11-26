# Network Analyzer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-orange.svg)

Комплексная диагностика сетевой конфигурации для Debian 12 / Ubuntu 20+ / Proxmox

`network-analyzer.sh` — это расширенный скрипт для автоматической диагностики сети, сбора конфигураций, поиска ошибок и анализа работы сетевых компонентов Linux-системы. Подходит для серверов, рабочих станций, виртуальных машин и инфраструктур с Proxmox / Docker / VPN / Firewall.

Скрипт создаёт **подробный txt-отчёт** в каталоге рядом с собой, а также выводит результат в терминал (с цветовым форматированием).

---

## Возможности

Скрипт последовательно собирает и анализирует:

### 1. Общая системная информация

* hostname, FQDN, domain
* версия ОС, ядро
* файлы `/etc/hostname`, `/etc/hosts`, `resolv.conf`

### 2. Сетевые интерфейсы

* список интерфейсов (ip -br)
* полная конфигурация `ip addr`
* скорость линка (`ethtool`)
* статистика RX/TX
* состояние каналов и ошибок
* устаревший `ifconfig` (если доступен)

### 3. Маршрутизация

* IPv4/IPv6 маршруты
* все таблицы маршрутизации
* policy routing (`ip rule`)
* IP forwarding

### 4. ARP / Neighbor таблицы

* ARP IPv4
* NDP IPv6
* `arp -a` (если доступно)

### 5. DNS

* анализ resolv.conf и systemd-resolved
* `resolvectl status`
* тест резолвинга через host

### 6. Сетевые соединения

* слушающие порты
* установленные TCP/UDP соединения
* статистика состояний
* `netstat` (если доступен)

### 7. Firewall

* iptables: filter, nat, mangle
* nftables ruleset
* ufw / firewalld (если установлены)

### 8. NAT и Port Forwarding

* SNAT/MASQUERADE
* DNAT
* состояние conntrack
* top-записи соединений

### 9. Wi-Fi (если есть)

* интерфейсы
* iw / iwconfig
* nmcli
* сканирование сетей
* сохранённые Wi-Fi-профили (root)

### 10. VPN

* OpenVPN
* WireGuard
* IPsec
* PPTP (если настроен)

### 11. Мосты и VLAN

* bridge
* VLAN-интерфейсы
* Open vSwitch

### 12. Bonding / Teaming

* /proc/net/bonding/*
* teamdctl

### 13. QoS / Traffic Control

* qdisc
* class
* tc filters

### 14. Proxy

* env proxy
* APT proxy
* Squid
* SOCKS на порту 1080

### 15. DHCP

* client leases
* dhcpd
* dnsmasq (если работает)

### 16. NetworkManager

* подключения
* устройства
* конфиги system-connections

### 17. Netplan / systemd-networkd

* YAML-конфиги
* status networkd

### 18. Docker сети

* список сетей
* inspect (структура, subnet, gateway)

### 19. Статистика трафика

* RX/TX counters
* vnstat / iftop (если установлены)

### 20. Сетевые сервисы

* HTTP, mail, DB, SSH
* состояние nginx / apache

### 21. Сетевая безопасность

* hosts.allow / deny
* sysctl net.*
* fail2ban

### 22. IPv6

* адреса
* маршруты
* параметры ядра
* NDP

### 23. Туннели

* GRE
* IPIP
* SIT (6in4)

### 24. Multicast

* mroute
* IGMP

### 25. Диагностические тесты

* ping loopback
* ping gateway
* DNS test
* traceroute (если установлен)

### 26. Логи

* NetworkManager
* systemd-networkd
* kernel network events
* syslog

### 27. Производительность сети

* TCP buffers
* congestion control
* netdev backlog
* softnet статистика

### Итоговый анализ

Скрипт оценивает:

* режим работы (router, NAT, proxy, firewall)
* активные интерфейсы
* общее состояние сети

---

## Вывод отчётов

Скрипт автоматически сохраняет полный отчёт:

```
network-analyzer-YYYYMMDD-HHMMSS.txt
```

Файл создаётся **рядом с самим скриптом**.
Из терминала вывод остаётся цветным, а в файл записывается чистый текст (ANSI-коды очищены).

---

## Требования

**Обязательные утилиты:**

* iproute2 (`ip`, `ss`)
* grep, awk, sed

**Опциональные (рекомендуемые):**

* ethtool
* nmcli
* iptables/nftables
* docker
* traceroute
* conntrack
* tcpdump
* bridge-utils
* wlan-tools
* fail2ban

Скрипт сам проверяет наличие утилит и сообщает, если чего-то не хватает.

---

## Установка и использование
# Скопируйте скрипт
```
wget https://github.com/saym101/network-analyzer/raw/refs/heads/main/network-analyzer.sh
```

### 1. Сделать исполняемым:

```bash
chmod +x network-analyzer.sh
```

### 2. Запустить стандартный анализ:

```bash
./network-analyzer.sh
```

### 3. Быстрый режим:

```bash
./network-analyzer.sh --quick
```

### 4. Глубокий анализ:

```bash
./network-analyzer.sh --deep
```

### 5. Показать Wi-Fi-пароли (root):

```bash
sudo ./network-analyzer.sh --with-passwords
```

### 6. Сохранить отчёт под своим именем:

```bash
./network-analyzer.sh --txt myreport.txt
```

---

## Особенности

* Скрипт устойчив к ошибкам (fail-safe):
  сбой одной команды не прерывает анализ.
* ANSI-коды автоматически очищаются при записи в файл.
* Поддержка Proxmox: корректная работа на pve-хостах.
* Не требует внешних зависимостей, кроме стандартных утилит.

---

## Лицензия

MIT ![License](https://img.shields.io/badge/license-MIT-blue.svg)
---
