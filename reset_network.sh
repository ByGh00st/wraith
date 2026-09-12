#!/bin/bash
# Ağ bağlantısını ve güvenlik duvarını sıfırlama (Emergency Network Reset)

if [ "$EUID" -ne 0 ]; then
  echo "Lütfen bu betiği root (sudo) yetkisiyle çalıştırın."
  exit 1
fi

echo "[*] Ağ ayarları ve Firewall kuralları sıfırlanıyor..."

# 1. Tor ve Wraith işlemlerini durdur (arka planda asılı kalmış olabilir)
echo "[*] Tor ve Wraith işlemleri durduruluyor..."
killall wraith 2>/dev/null
killall tor 2>/dev/null
systemctl stop tor 2>/dev/null

# 2. Iptables ve IPv6 kurallarını sıfırla
echo "[*] Iptables ve Ip6tables kuralları temizleniyor..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

ip6tables -F
ip6tables -X
ip6tables -t nat -F
ip6tables -t nat -X
ip6tables -t mangle -F
ip6tables -t mangle -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

# 3. DNS Ayarlarını Düzelt
echo "[*] DNS çözücü (/etc/resolv.conf) sıfırlanıyor..."
rm -f /etc/resolv.conf
# Çoğu sistemde /run/systemd/resolve/stub-resolv.conf veya benzeri bir dosya vardır
# NetworkManager tekrar oluşturacaktır, şimdilik geçici bir DNS atayalım
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# 4. Traffic Control (tc) qdisc temizliği
echo "[*] Traffic Control (tc) kısıtlamaları kaldırılıyor..."
for iface in $(ls /sys/class/net/); do
    tc qdisc del dev $iface root 2>/dev/null
done

# 5. NetworkManager'ı Yeniden Başlat
echo "[*] NetworkManager servisi yeniden başlatılıyor..."
systemctl restart NetworkManager

echo "[+] Sıfırlama tamamlandı. Ağ bağlantınızın birkaç saniye içinde geri gelmesi bekleniyor."
