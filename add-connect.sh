#!/bin/bash

# Function to generate a random port that is not currently in use
get_port() {
	echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 ))
}

check_free() {
	local port=$1
	nc -z 127.0.0.1 $port &>/dev/null
	return $?
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

# Generate necessary ports and paths
sub_port=$(make_port)
panel_port=$(make_port)
sub_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
json_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
panel_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")
ws_port=$(make_port)
ws_path=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n 1)")

# Get the current domain from the x-ui database
XUIDB="/etc/x-ui/x-ui.db"
if [[ -f $XUIDB ]]; then
    domain=$(sqlite3 -list $XUIDB 'SELECT "value" FROM settings WHERE "key"="webDomain" LIMIT 1;' 2>&1)
    if [[ -z "$domain" ]]; then
        echo "Domain not found in the x-ui database."
        exit 1
    fi
else
    echo "x-ui database not found."
    exit 1
fi

# Get the reality domain from the user
read -p "Enter the subdomain for Reality (sub.domain.tld): " reality_domain

reality_domain=$(echo "$reality_domain" 2>&1 | tr -d '[:space:]')
RealitySubDomain=$(echo "$reality_domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
RealityMainDomain=$(echo "$reality_domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')
if [[ "${RealitySubDomain}.${RealityMainDomain}" != "${reality_domain}" ]] ; then
	RealityMainDomain=${reality_domain}
fi

# Generate SSL certificates for the domains
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$domain"
if [[ ! -d "/etc/letsencrypt/live/${domain}/" ]]; then
    echo "SSL for $domain could not be generated! Check Domain/IP or Enter new domain!"
    exit 1
fi

certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$reality_domain"
if [[ ! -d "/etc/letsencrypt/live/${reality_domain}/" ]]; then
    echo "SSL for $reality_domain could not be generated! Check Domain/IP or Enter new domain!"
    exit 1
fi

# Update nginx configuration
cat > "/etc/nginx/stream-enabled/stream.conf" << EOF
map \$ssl_preread_server_name \$sni_name {
    hostnames;
    ${reality_domain}      xray;
    ${domain}           www;
    default              xray;
}

upstream xray {
    server 127.0.0.1:8443;
}

upstream www {
    server 127.0.0.1:7443;
}

server {
    proxy_protocol on;
    set_real_ip_from unix:;
    listen          443;
    proxy_pass      \$sni_name;
    ssl_preread     on;
}
EOF

grep -xqFR "stream { include /etc/nginx/stream-enabled/*.conf; }" /etc/nginx/* ||echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
grep -xqFR "load_module modules/ngx_stream_module.so;" /etc/nginx/* || sed -i '1s/^/load_module \/usr\/lib\/nginx\/modules\/ngx_stream_module.so; /' /etc/nginx/nginx.conf

cat > "/etc/nginx/sites-available/$domain" << EOF
server {
	server_tokens off;
	server_name ${domain};
	listen 7443 ssl http2 proxy_protocol;
	listen [::]:7443 ssl http2 proxy_protocol;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
	if (\$host !~* ^(.+\.)?$domain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$domain\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel
	location /${panel_path}/ {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:${panel_port};
		break;
	}
        location /${panel_path} {
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:${panel_port};
		break;
	}
 	#Subscription Path (simple/encode)
        location /${sub_path} {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:${sub_port};
                break;
        }
	location /${sub_path}/ {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:${sub_port};
                break;
        }
	#Subscription Path (json/fragment)
        location /${json_path} {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:${sub_port};
                break;
        }
	location /${json_path}/ {
                if (\$hack = 1) {return 404;}
                proxy_redirect off;
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:${sub_port};
                break;
        }
 	#Xray Config Path
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
		if (\$content_type ~* "GRPC") {
			grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
		if (\$http_upgrade ~* "(WEBSOCKET|WS)") {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
	        }
		if (\$request_method ~* ^(PUT|POST|GET)\$) {
			proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
			break;
		}
	}
	location / { try_files \$uri \$uri/ =404; }
}
EOF

ln -s "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/"
ln -s "/etc/nginx/sites-available/80.conf" "/etc/nginx/sites-enabled/"

if [[ $(nginx -t 2>&1 | grep -o 'successful') != "successful" ]]; then
    echo "nginx config is not ok!"
    exit 1
else
    systemctl restart nginx
fi

# Update x-ui database with new ports and paths
if [[ -f $XUIDB ]]; then
    x-ui stop
    var1=$(/usr/local/x-ui/bin/xray-linux-amd64 x25519)
    var2=($var1)
    private_key=${var2[2]}
    public_key=${var2[5]}
    client_id=$(/usr/local/x-ui/bin/xray-linux-amd64 uuid)
    sqlite3 $XUIDB <<EOF
    INSERT INTO "inbounds" ("user_id","up","down","total","remark","enable","expiry_time","listen","port","protocol","settings","stream_settings","tag","sniffing","allocate") VALUES ( 
        '1',
	    '0',
        '0',
	    '0',
        'reality',
	    '1',
        '0',
	    '',
        '8443',
	    'vless',
        '{
	    "clients": [
            {
                "id": "${client_id}",
                "flow": "xtls-rprx-vision",
                "email": "first",
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": true,
                "tgId": "",
                "subId": "first",
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
                "dest": "$domain",
                "port": 443,
                "remark": ""
            }
        ],
        "realitySettings": {
            "show": false,
            "xver": 0,
            "dest": "${reality_domain}:9443",
            "serverNames": [
                "$reality_domain"
            ],
            "privateKey": "${private_key}",
            "minClient": "",
            "maxClient": "",
            "maxTimediff": 0,
            "shortIds": [
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)",
                "$(openssl rand -hex 8)"
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
        'inbound-8443',
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
    x-ui start
else
    echo "x-ui.db file not exist! Maybe x-ui isn't installed."
    exit 1
fi

echo "New Reality connection added successfully!"