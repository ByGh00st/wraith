#!/bin/bash
# Wraith Update Script (Source-only)
# Yalnızca kaynak kodunu indirir, derleme işlemini yapmaz.

echo "[*] Wraith kaynak kodları güncelleniyor..."

# Eğer betik git dizini içindeyse, doğrudan git pull yap
if [ -d ".git" ]; then
    echo "[*] Mevcut depo (git repository) güncelleniyor..."
    git fetch --all
    git reset --hard origin/main
    git pull origin main
else
    # Eğer git dizini değilse, bulunulan konuma (current dir) klonla
    echo "[*] Git dizini bulunamadı. Kaynak kodları bu dizine indiriliyor..."
    sudo rm -rf wraith-source-update
    sudo git clone https://github.com/ByGh00st/wraith.git wraith-source-update
    echo "[+] Kodlar 'wraith-source-update' dizinine başarıyla indirildi."
    echo "[+] Güncellemek için dizine gidip derleme komutunu çalıştırın:"
    echo "    cd wraith-source-update && sudo ./build.sh"
    exit 0
fi

echo "[+] Kaynak kodlar başarıyla güncellendi."
echo "[+] 101 OOM hatası almamak için derleme işlemini lütfen manuel olarak başlatın:"
echo "    sudo ./build.sh"
