#!/bin/bash
set -euo pipefail

# Проверка прав root
if [[ $EUID -ne 0 ]]; then
   echo "Этот скрипт должен быть запущен с правами root" 
   exit 1
fi

# Проверка зависимостей
for cmd in sqlite3 nginx certbot openssl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Ошибка: $cmd не установлен"
        exit 1
    fi
done

# Функция для генерации случайного порта
get_port() {
    echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 ))
}

check_free() {
    local port=$1
    if ss -tuln | grep -q ":$port "; then
        return 0  # порт занят
    else
        return 1  # порт свободен
    fi
}

make_port() {
    while true; do
        PORT=$(get_port)
        if ! check_free $PORT; then 
            echo $PORT
            break
        fi
    done
}

# Остановка сервисов перед изменениями
systemctl stop x-ui
systemctl stop nginx

# Генерация необходимых портов и путей
sub_port=$(make_port)
panel_port=$(make_port)
sub_path=$(openssl rand -hex 6)
json_path=$(openssl rand -hex 6)
panel_path=$(openssl rand -hex 6)
ws_port=$(make_port)
ws_path=$(openssl rand -hex 6)

# Получение текущего домена из базы данных x-ui
XUIDB="/etc/x-ui/x-ui.db"
if [[ ! -f $XUIDB ]]; then
    echo "База данных x-ui не найдена."
    exit 1
fi

domain=$(sqlite3 -list $XUIDB 'SELECT "value" FROM settings WHERE "key"="webDomain" LIMIT 1;' 2>&1)
if [[ -z "$domain" ]]; then
    echo "Домен не найден в базе данных x-ui."
    exit 1
fi

# Получение Reality домена от пользователя
read -p "Введите поддомен для Reality (sub.domain.tld): " reality_domain
reality_domain=$(echo "$reality_domain" | tr -d '[:space:]')

# Генерация SSL сертификатов
echo "Получение сертификатов для доменов..."
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$domain" -d "$reality_domain"

if [[ ! -d "/etc/letsencrypt/live/${domain}/" ]]; then
    echo "Не удалось получить SSL для $domain! Проверьте домен/IP или введите новый домен!"
    exit 1
fi

if [[ ! -d "/etc/letsencrypt/live/${reality_domain}/" ]]; then
    echo "Не удалось получить SSL для $reality_domain! Проверьте домен/IP или введите новый домен!"
    exit 1
fi

# Обновление 80.conf
if [[ ! -f "/etc/nginx/sites-available/80.conf" ]]; then
    cat > "/etc/nginx/sites-available/80.conf" << EOF
server {
    listen 80;
    server_name $domain $reality_domain;
    return 301 https://\$host\$request_uri;
}
EOF
else
    # Проверяем, есть ли уже домен в конфиге 80.conf
    if ! grep -q "server_name .*$reality_domain" "/etc/nginx/sites-available/80.conf"; then
        sed -i "/server_name/s/;/ $reality_domain;/" "/etc/nginx/sites-available/80.conf"
    fi
fi

# Проверка корректности 80.conf
if ! nginx -t -c /etc/nginx/nginx.conf; then
    echo "Ошибка в конфигурации nginx (80.conf)"
    exit 1
fi

# Генерация уникального upstream имени
unique_upstream="xray$(tr -dc A-Za-z </dev/urandom | head -c 6)"

# Генерация случайного порта для нового серверного блока
new_port=$(make_port)

# Генерация случайного имени пользователя и заметки
username_random=$(openssl rand -hex 4)
remark_random=$(openssl rand -hex 4)

# Определение следующего доступного inbound_id
inbound_id=1
while sqlite3 -list $XUIDB "SELECT * FROM inbounds WHERE id = $inbound_id" 2>/dev/null | grep -q .; do
    ((inbound_id++))
done

# Генерация short IDs
shor=($(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8) $(openssl rand -hex 8))

# Обновление конфигурации nginx
stream_conf="/etc/nginx/stream-enabled/stream.conf"

# Проверка существования upstream
if ! grep -q "^upstream $unique_upstream {" "$stream_conf"; then
    cat >> "$stream_conf" << EOF

upstream $unique_upstream {
    server 127.0.0.1:$new_port;
}
EOF
fi

# Добавление server block если его нет
if ! grep -q "map \$ssl_preread_server_name \$sni_name {" "$stream_conf"; then
    cat > "$stream_conf" << EOF
map \$ssl_preread_server_name \$sni_name {
    hostnames;
    ${reality_domain}      $unique_upstream;
    ${domain}           www;
    default              xray;
}
EOF
else
    # Вставка нового server block перед строкой default
    sed -i "/default\s*xray;/i ${reality_domain}      $unique_upstream;" "$stream_conf"
fi

# Создание нового server block для reality_domain
cat > "/etc/nginx/sites-available/${reality_domain}" << EOF
server {
    server_tokens off;
    server_name ${reality_domain};
    listen ${new_port} ssl http2;
    listen [::]:${new_port} ssl http2;
    index index.html index.htm index.php index.nginx-debian.html;
    root /var/www/html/;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_certificate /etc/letsencrypt/live/$reality_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$reality_domain/privkey.pem;
    if (\$host !~* ^(.+\.)?${reality_domain}\$ ){return 444;}
    if (\$scheme ~* https) {set \$safe 1;}
    if (\$ssl_server_name !~* ^(.+\.)?${reality_domain}\$ ) {set \$safe "\${safe}0"; }
    if (\$safe = 10){return 444;}
    if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
    error_page 400 401 402 403 500 501 502 503 504 =404 /404;
    proxy_intercept_errors on;
    
    # X-UI Admin Panel
    location /${panel_path}/ {
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:${panel_port};
        break;
    }
    
    # Subscription Paths
    location /${sub_path} {
        if (\$hack = 1) {return 404;}
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:${sub_port};
        break;
    }
    
    location /${json_path} {
        if (\$hack = 1) {return 404;}
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:${sub_port};
        break;
    }
    
    # Xray Config Path
    location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
        if (\$hack = 1) {return 404;}
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        if (\$request_method ~* ^(PUT|POST|GET)\$) {
            proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
    }
    
    location / { try_files \$uri \$uri/ =404; }
}
EOF

# Активация конфигурации сайта
ln -sf "/etc/nginx/sites-available/${reality_domain}" "/etc/nginx/sites-enabled/"

# Проверка конфигурации nginx и перезапуск
if ! nginx -t; then
    echo "Ошибка в конфигурации nginx!"
    exit 1
fi

systemctl restart nginx

# Генерация новых клиентских ID и ключей
var1=$(/usr/local/x-ui/bin/xray-linux-amd64 x25519)
var2=($var1)
private_key=${var2[2]}
public_key=${var2[5]}
client_id=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)

# Обновление базы данных x-ui
sqlite3 $XUIDB <<EOF
INSERT INTO "client_traffics" ("inbound_id","enable","email","up","down","expiry_time","total","reset") VALUES ('${inbound_id}','1','${username_random}','0','0','0','0','0');
INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing","allocate") VALUES ( 
    '${inbound_id}',
    '0',
    '0',
    '0',
    'reality_${remark_random}',
    '1',
    '0',
    '',
    '${new_port}',
    'vless',
    '{
    "clients": [
        {
            "id": "${client_id}",
            "flow": "xtls-rprx-vision",
            "email": "${username_random}",
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": true,
            "tgId": "",
            "subId": "${username_random}",
            "reset": 0
        }
    ],
    "decryption": "none",
    "fallbacks": []
    }',
    '{
    "network": "tcp",
    "security": "reality",
    "externalProxy": [
        {
            "forceTls": "same",
            "dest": "${domain}",
            "port": 443,
            "remark": ""
        }
    ],
    "realitySettings": {
        "show": false,
        "xver": 0,
        "dest": "${reality_domain}:${new_port}",
        "serverNames": [
            "${reality_domain}"
        ],
        "privateKey": "${private_key}",
        "minClient": "",
        "maxClient": "",
        "maxTimediff": 0,
        "shortIds": [
            "${shor[0]}",
            "${shor[1]}",
            "${shor[2]}",
            "${shor[3]}",
            "${shor[4]}",
            "${shor[5]}",
            "${shor[6]}",
            "${shor[7]}"
        ],
        "settings": {
            "publicKey": "${public_key}",
            "fingerprint": "random",
            "serverName": "",
            "spiderX": "/"
        }
    },
    "tcpSettings": {
        "acceptProxyProtocol": true,
        "header": {
            "type": "none"
        }
    }
    }',
    'inbound-${new_port}',
    '{
    "enabled": false,
    "destOverride": [
        "http",
        "tls",
        "quic",
        "fakedns"
    ],
    "metadataOnly": false,
    "routeOnly": false
    }',
    '{
    "strategy": "always",
    "refresh": 5,
    "concurrency": 3
    }'
);
EOF

# Запуск x-ui
systemctl start x-ui

echo "Новое Reality подключение успешно добавлено с заметкой: reality_${remark_random}"
echo "Данные для подключения:"
echo "Адрес: ${reality_domain}"
echo "Порт: 443"
echo "ID: ${client_id}"
echo "Flow: xtls-rprx-vision"
echo "Public Key: ${public_key}"
echo "Short ID: ${shor[0]}"
