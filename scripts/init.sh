#!/usr/bin/env bash

# stop script on first error
set -e

# write last error and fail
function fail() {
  echo "$1" >&2
  echo "$1" >> /root/fail.log
  exit 1
}

# fail if script was already executed
[[ -f /root/initdone ]] && fail "already initialized"
touch /root/initdone

# install utils with retry
i=1
until apt-get update > /dev/null
do
  sleep 10
  echo "retry apt-get update"
  (( i++ > 10 )) && fail "not able to update packages"
done

i=1
until apt-get install -y jq sysstat > /dev/null
do
  sleep 10
  echo "retry apt-get update"
  (( i++ > 10 )) && fail "not able to install tools"
done

# read script parameters
CONFIG_BASE64=${1}
IP=${2}
FQDN=${3}

# check all parameters are available
[[ -z "${CONFIG_BASE64}" ]] && fail "no configuration was provided"
[[ -z "${IP}" ]] && fail "no ip address was provided"
[[ -z "${FQDN}" ]] && fail "no fqdn was provided"

# decode base 64 configuration and write to file
CONFIG_FILE=/root/config.json 
echo "${CONFIG_BASE64}" | base64 -d > ${CONFIG_FILE}

# read configuration data into environment variables, missing should be empty string, not "null"
ADMIN_USER=$(jq -r ."os_user // empty" "${CONFIG_FILE}")
CHAIN_NAME=$(jq -r ."chain_name // empty" "${CONFIG_FILE}")
CHAIN_DESCRIPTION=$(jq -r ."chain_description // empty" "${CONFIG_FILE}")
SEED_NODE_URL=$(jq -r ."seed_node // empty" "${CONFIG_FILE}")
EMAIL=$(jq -r ."email // empty" "${CONFIG_FILE}")
CREATE_PARAMETERS_INPUT=$(jq -r ."create_parameters // empty" "${CONFIG_FILE}")
RUNTIME_FLAGS_INPUT=$(jq -r ."runtime_flags // empty" "${CONFIG_FILE}")
MODE=$(jq -r ."mode // empty" "${CONFIG_FILE}")
CERTTYPE=$(jq -r ."certtype // empty" "${CONFIG_FILE}")
POST_SCRIPT=$(jq -r ."post_script // empty" "${CONFIG_FILE}")

# check all mandatory parameters are set
[[ -z "${ADMIN_USER}" ]] && fail "no os_user was provided"
[[ "${ADMIN_USER}" == "multichain" ]] && fail "os_user may not be: multichain"
[[ -z "${CHAIN_NAME}" ]] && fail "no chain name was provided"
[[ -z "${CERTTYPE}" ]] && fail "no certtype was provided"
[[ -z "${MODE}" ]] && fail "no deployment mode was provided"
[[ "${MODE}" == "join" ]] && [[ -z "${SEED_NODE_URL}" ]] && fail "no seed node was provided"

CHAIN_DESCRIPTION_PARAM=""
[[ -n "${CHAIN_DESCRIPTION}" ]] && CHAIN_DESCRIPTION_PARAM="-chain-description=\"${CHAIN_DESCRIPTION}\""

# add seed node to connect string if set
CONNECT_STRING="${CHAIN_NAME}"
[[ "${MODE}" == "join" ]] && CONNECT_STRING="${CHAIN_NAME}@${SEED_NODE_URL}"

# add multichain user that will run the multichain
MC_OS_USER=multichain
MC_OS_GROUP=multichain
MC_OS_USER_HOME=/home/${MC_OS_USER}

useradd -m ${MC_OS_USER}

# set additional variables
EXTERNAL_FLAG="-externalip=${IP}"
BASIC_AUTH_USER=multichain
BASIC_AUTH_PASSWORD=$(tr -dc a-zA-Z0-9 < /dev/urandom | fold -w 64 | head -n 1)

MC_RPC_PORT=7999
MC_P2P_PORT=7000
MC_FOLDER=${MC_OS_USER_HOME}/.multichain
MC_CONFIG=${MC_FOLDER}/multichain.conf
MC_CHAIN_FOLDER=${MC_FOLDER}/${CHAIN_NAME}
MC_CHAIN_CONFIG=${MC_CHAIN_FOLDER}/multichain.conf
MC_PID_LOCATION=${MC_OS_USER_HOME}/multichain.pid
MC_LOCAL_RPC=http://127.0.0.1:${MC_RPC_PORT}
MC_P2P_ENDPOINT=${CHAIN_NAME}@${IP}:${MC_P2P_PORT}
MC_DOWNLOAD_URL=https://www.multichain.com/download/multichain-2.0-latest.tar.gz
MC_VERSION_URL=https://www.multichain.com/download/multichain-2.0-latest.json
MC_DASHBOARD_PHP_URL=https://www.multichain.com/download/multichain-2.0-azure-dashboard-php.txt
MC_START_SCRIPT=${MC_OS_USER_HOME}/start.sh
MC_DIAGNOSTIC_SCRIPT=${MC_OS_USER_HOME}/diagnostics.sh
MC_LOG_SCRIPT=${MC_OS_USER_HOME}/getdebuglog.sh
MC_CHECK_SCRIPT=/root/multichain-check-latest.sh
MC_DOWNLOAD_SCRIPT=/root/multichain-download-latest.sh
MC_INSTALL_SCRIPT=/root/multichain-install.sh
MC_SERVICE_SCRIPT=/root/systemctl-multichain.sh
MC_SERVICE_FILE=/lib/systemd/system/multichain.service

# use unsafely only if no registration email was provided for certbot (letsencrypt)
CERTBOT_FLAG="--register-unsafely-without-email"
[[ -n "${EMAIL}" ]] && CERTBOT_FLAG="-m ${EMAIL}"

# if no TLS should be used set nginx port and listen directive accordingly
[[ "${CERTTYPE}" == "disabled" ]] && NGINX_PORT=80 || NGINX_PORT=443
[[ "${CERTTYPE}" == "disabled" ]] && NGINX_LISTEN="listen ${NGINX_PORT};" || NGINX_LISTEN="listen ${NGINX_PORT} ssl;"

NGINX_HTPASSWD_FILE=/etc/nginx/htpasswd
NGINX_CONFIG_FILE=/etc/nginx/nginx.conf
NGINX_SERVICE_FILE=/lib/systemd/system/nginx.service
NGINX_RELOAD_SCRIPT=/etc/letsencrypt/renewal-hooks/deploy/reload_nginx.sh


# create script to check latest version
cat <<EOF >${MC_CHECK_SCRIPT}
wget -q -O - ${MC_VERSION_URL}
EOF

# create script to download latest multichain 2.0
cat <<EOF >${MC_DOWNLOAD_SCRIPT}
cd /tmp
rm -rf multichain*
curl -sL --retry 10 --connect-timeout 10 --retry-delay 10 --retry-max-time 600 -o multichain.tar.gz ${MC_DOWNLOAD_URL}
tar -xvzf multichain.tar.gz
mv multichain-* multichain-install
curl -sL --retry 10 --connect-timeout 10 --retry-delay 10 --retry-max-time 600 -o multichain-install/version.json ${MC_VERSION_URL}
EOF

# create script to install downloaded multichain
cat <<EOF >${MC_INSTALL_SCRIPT}
cd /tmp/multichain-install
mv multichaind multichain-cli multichain-util /usr/local/bin
cd ..
rm -rf multichain*
EOF

# run the script to download and install latest multichain 2.0
chmod 700 ${MC_DOWNLOAD_SCRIPT} ${MC_INSTALL_SCRIPT} ${MC_CHECK_SCRIPT}
${MC_DOWNLOAD_SCRIPT}
${MC_INSTALL_SCRIPT}


# retrieve certificate using letsencrypt certbot
if [[ "${CERTTYPE}" == "letsencrypt" ]]
then
    add-apt-repository -y ppa:certbot/certbot
    # install certbot with retry
    i=1
    until apt-get install -y certbot > /dev/null
    do
      sleep 10
      echo "retry apt-get install certbot"
      (( i++ > 10 )) && fail "not able to install certbot"
    done

    certbot certonly --agree-tos "${CERTBOT_FLAG}" --domain "${FQDN}" --standalone
    SSL_CERT=/etc/letsencrypt/live/${FQDN}/fullchain.pem;
    SSL_KEY=/etc/letsencrypt/live/${FQDN}/privkey.pem;

# this will be executed when new letsencrypt certificate arrives
cat <<EOF > ${NGINX_RELOAD_SCRIPT}
#!/usr/bin/env bash
systemctl reload nginx
EOF
chmod 700 ${NGINX_RELOAD_SCRIPT}

fi

# install and configure nginx as reverse proxy with retry
i=1
until apt-get install -y nginx php-fpm > /dev/null
do
  sleep 10
  echo "retry apt-get install nginx"
  (( i++ > 10 )) && fail "not able to install nginx"
done

# create a self signed certificate
if [[ "${CERTTYPE}" == "self" ]]
then
    SSL_CERT=/etc/nginx/cert.pem;
    SSL_KEY=/etc/nginx/key.pem;

# TODO: put here whatever you want since it is a self signed cert
cat <<EOF > /root/req.conf
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = UK
L = London
O = CoinSciences
OU = MultiChain
CN = ${FQDN}
[v3_req]
keyUsage = keyCertSign,keyEncipherment,dataEncipherment
basicConstraints = CA:TRUE,pathlen:0
extendedKeyUsage = serverAuth
subjectAltName = @subject_alt_name
[subject_alt_name]
DNS.1 = ${FQDN}
IP.1 = ${IP}
EOF

    openssl req -x509 -newkey rsa:4096 -keyout ${SSL_KEY} -out ${SSL_CERT} -days 36500 -nodes -config /root/req.conf
    chmod 664 ${SSL_CERT}
    chmod 600 ${SSL_KEY}
fi


# nginx config

# basic auth
echo -n "${BASIC_AUTH_USER}:" > ${NGINX_HTPASSWD_FILE}
echo "${BASIC_AUTH_PASSWORD}" | openssl passwd -apr1 -stdin >> ${NGINX_HTPASSWD_FILE}

# ssl check
[[ "${CERTTYPE}" != "disabled" ]] && NGINX_CERT="ssl_certificate ${SSL_CERT};"
[[ "${CERTTYPE}" != "disabled" ]] && NGINX_KEY="ssl_certificate_key ${SSL_KEY};"

#php file may vary in version so to be sure grab the exact file
PHP_SOCK=$(ls /var/run/php/php*sock)
[[ -z "${PHP_SOCK}" ]] && fail "could not retrieve php-sock file"

# create minimal nginx config
cat <<EOF > ${NGINX_CONFIG_FILE}
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
  worker_connections 512;
}

http {
  server {
    ${NGINX_LISTEN}
    server_name ${FQDN};
  
    ${NGINX_CERT}
    ${NGINX_KEY}
  
    location / {
      proxy_pass ${MC_LOCAL_RPC}/;
      proxy_read_timeout 3600s;
    }
  
    location /dashboard {
      auth_basic "Login";
      auth_basic_user_file ${NGINX_HTPASSWD_FILE};
  
      alias /var/www/html;
      index index.php;
  
      location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$request_filename;
        fastcgi_pass unix:${PHP_SOCK};
      }
    }
  }
  
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_protocols TLSv1.2;
  ssl_prefer_server_ciphers on;
  
  keepalive_timeout 60;
  
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
}
EOF
systemctl restart nginx

# make nginx service robust and directly restart it if stopped / killed
if [[ -f "${NGINX_SERVICE_FILE}" ]]
then
    if ! grep -siq "Restart=" ${NGINX_SERVICE_FILE}
    then
        sed -i '/\[Service\]/a Restart=always' ${NGINX_SERVICE_FILE}
    fi
fi

# make php service robust and directly restart it if stopped / killed
PHP_SERVICE=$(ls /lib/systemd/system/php*fpm*service)
if [[ -f "${PHP_SERVICE}" ]]
then
    if ! grep -siq "Restart=" ${PHP_SERVICE}
    then
        sed -i '/\[Service\]/a Restart=always' ${PHP_SERVICE}
    fi
fi

systemctl daemon-reload

# create config files upfront since we don't want it to be filled by multichain
mkdir -p ${MC_CHAIN_FOLDER}
touch ${MC_CONFIG} ${MC_CHAIN_CONFIG}
chown -R ${MC_OS_USER}:${MC_OS_GROUP} ${MC_FOLDER}
chmod 700 ${MC_FOLDER} ${MC_CHAIN_FOLDER}
chmod 600 ${MC_CONFIG} ${MC_CHAIN_CONFIG}

# if mode is create, we create a new multichain using the provided parameters
if [[ "${MODE}" == "create" ]]
then
    CREATE_PARAMETERS_LIST=""
    # if create parameters are provided transform them ino correct format
    if [[ -n "${CREATE_PARAMETERS_INPUT}" ]]
    then
        # (1) remove all spaces, (2) remove last ";" (3) replace ";"  by " -", (4) add another "-" at the beginning
        CREATE_PARAMETERS_LIST=$(echo "${CREATE_PARAMETERS_INPUT}" | sed -r 's/ +//g; s/;$//g; s/;/ -/g; s/^/-/g')
    fi
    # create the chain using correct user
    su - -c "multichain-util create ${CHAIN_NAME} ${CREATE_PARAMETERS_LIST}" ${MC_OS_USER}
fi

# truncate chain specific multichain file and add mandatory flags
echo "rpcuser=${BASIC_AUTH_USER}" > ${MC_CHAIN_CONFIG}
echo "rpcpassword=${BASIC_AUTH_PASSWORD}" >> ${MC_CHAIN_CONFIG}
echo "storeruntimeparams=1" >> ${MC_CHAIN_CONFIG}
echo "retryinittime=30000000" >> ${MC_CHAIN_CONFIG}
if [[ -n "${RUNTIME_FLAGS_INPUT}" ]]
then
    # if runtime flags are provided transform them in the correct format and append them to chain specific multichain.conf
    # put all flags that provide a value directly in the config file, for flags without value we append "=1" as default value
    echo "${RUNTIME_FLAGS_INPUT}" | sed -r 's/ +//g; s/;$//g; s/;/\n/g' | grep "=" >> ${MC_CHAIN_CONFIG}
    echo "${RUNTIME_FLAGS_INPUT}" | sed -r 's/ +//g; s/;$//g; s/;/\n/g' | grep -v "=" | sed -r 's/$/=1/g' >> ${MC_CHAIN_CONFIG}
    # debug flag needs special treatment since it can have an empty string as value, so replace =1 (the default) with just =
    sed -i 's/debug=1/debug=/g' ${MC_CHAIN_CONFIG}
fi

# create a start script that is executed by systemd
cat <<EOF > ${MC_START_SCRIPT}
#!/usr/bin/env bash
multichaind -printtoconsole -daemon -pid=${MC_PID_LOCATION} -rpcport=${MC_RPC_PORT} -port=${MC_P2P_PORT} ${EXTERNAL_FLAG} ${CONNECT_STRING}
EOF
chown ${MC_OS_USER}:${MC_OS_GROUP} ${MC_START_SCRIPT}
chmod 700 ${MC_START_SCRIPT}

# configure multichain as systemd service for automatic restart after crash
cat <<EOF > ${MC_SERVICE_FILE}
[Unit]
Description=MultiChain

[Service]
Type=simple
User=${MC_OS_USER}
WorkingDirectory=${MC_OS_USER_HOME}
ExecStart=${MC_START_SCRIPT}

Restart=always
TimeoutStopSec=600

SyslogIdentifier=multichain

KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=yes

PIDFile=${MC_PID_LOCATION}

[Install]
WantedBy=multi-user.target
EOF

# enable multichain service
systemctl enable multichain

# create nginx-accessible script to start and stop node
cat <<EOF >$MC_SERVICE_SCRIPT
systemctl \$1 multichain
EOF

# create script to run diagnostic commands
cat <<EOF >${MC_DIAGNOSTIC_SCRIPT}
echo 'getinitstatus >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getinitstatus"}' ${MC_LOCAL_RPC}
echo '<<<<< getinitstatus | getinfo >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getinfo"}' ${MC_LOCAL_RPC}
echo '<<<<< getinfo | getblockchainparams >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getblockchainparams"}' ${MC_LOCAL_RPC}
echo '<<<<< getblockchainparams | getmempoolinfo >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getmempoolinfo"}' ${MC_LOCAL_RPC}
echo '<<<<< getmempoolinfo | getwalletinfo >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getwalletinfo"}' ${MC_LOCAL_RPC}
echo '<<<<< getwalletinfo | listblocks >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"listblocks","params":[-1, true]}' ${MC_LOCAL_RPC}
echo '<<<<< listblocks | getpeerinfo >>>>>'
curl -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getpeerinfo"}' ${MC_LOCAL_RPC}
echo '<<<<< getpeerinfo'
EOF

# create script to get debug log lines
cat <<EOF >${MC_LOG_SCRIPT}
journalctl -u multichain -e --no-pager -n 1000
EOF

# set ownership and permissions for nginx-accessible scripts
chown ${MC_OS_USER}:${MC_OS_GROUP} $MC_DIAGNOSTIC_SCRIPT $MC_LOG_SCRIPT
chmod 700 $MC_DIAGNOSTIC_SCRIPT $MC_LOG_SCRIPT $MC_SERVICE_SCRIPT

# allow nginx user to run specific scripts as multichain user
cat <<EOF >/etc/sudoers.d/www-data-multichain
www-data ALL=(${MC_OS_USER}) NOPASSWD:${MC_DIAGNOSTIC_SCRIPT}
www-data ALL=(${MC_OS_USER}) NOPASSWD:${MC_LOG_SCRIPT}
EOF

# allow nginx user to run specific scripts as root user
cat <<EOF >/etc/sudoers.d/www-data-root
www-data ALL=(root) NOPASSWD:$MC_SERVICE_SCRIPT
www-data ALL=(root) NOPASSWD:$MC_CHECK_SCRIPT
www-data ALL=(root) NOPASSWD:$MC_DOWNLOAD_SCRIPT
www-data ALL=(root) NOPASSWD:$MC_INSTALL_SCRIPT
EOF

# install monitoring page
rm -rf /var/www/html/* || true
curl -s -L --retry 10 --connect-timeout 10 --retry-delay 10 --retry-max-time 600 -o /var/www/html/index.php ${MC_DASHBOARD_PHP_URL}

# make sure all files are owned by the correct user
chown -R ${MC_OS_USER}:${MC_OS_GROUP} ${MC_OS_USER_HOME}/*

# start multichain
systemctl start multichain

# write tagged values in stdout for template to be able to grab them
PROTOCOL="https"
[[ "${CERTTYPE}" == "disabled" ]] && PROTOCOL="http"

echo "#rpcaddr#${PROTOCOL}://${FQDN}#rpcaddr#"
echo "#dashboard#${PROTOCOL}://${FQDN}/dashboard#dashboard#"
echo "#p2paddr#${MC_P2P_ENDPOINT}#p2paddr#"
echo "#authuser#${BASIC_AUTH_USER}#authuser#"
echo "#authpassword#${BASIC_AUTH_PASSWORD}#authpassword#"

# if using a self-signed certificate, the certificate is provided base64 encoded to the template output
CERT_BASE64="n/a"
[[ "${CERTTYPE}" == "self" ]] && CERT_BASE64=$(base64 -w0 ${SSL_CERT})
echo "#certificate#${CERT_BASE64}#certificate#"

# poll multichain for start up
curl -s -k --retry-connrefused --retry 60 --connect-timeout 2 --retry-delay 1 --retry-max-time 120 -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getinitstatus"}' ${MC_LOCAL_RPC}
sleep 5

# grab initial address to show it on script output
# first try getinitstatus, this will be set if the node is trying to connect
INITIAL_ADDRESS=$(curl -s -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getinitstatus"}' ${MC_LOCAL_RPC} | jq -r '.result.handshakelocal // empty')
# second try getpeerinfo, this will be set if the node is connected to another node
[[ -z "${INITIAL_ADDRESS}" ]] && INITIAL_ADDRESS=$(curl -s -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"getpeerinfo"}' ${MC_LOCAL_RPC} | jq -r '.result[0].handshakelocal // empty')
# third try listpermissions and grab the first address with connect permission
[[ -z "${INITIAL_ADDRESS}" ]] && INITIAL_ADDRESS=$(curl -s -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"listpermissions"}' ${MC_LOCAL_RPC} | jq -r '[ .result[] | select(.type=="connect") ]? | .[0].address // empty')
# last try listaddresses and just take the first address
[[ -z "${INITIAL_ADDRESS}" ]] && INITIAL_ADDRESS=$(curl -s -k -u${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD} --data-binary '{"method":"listaddresses"}' ${MC_LOCAL_RPC} | jq -r '.result[0].address // empty')
# still no luck? set to "n/a"
[[ -z "${INITIAL_ADDRESS}" ]] && INITIAL_ADDRESS="n/a"
echo "#initial_multichain_address#${INITIAL_ADDRESS}#initial_multichain_address#"

if [[ -n "${POST_SCRIPT}" ]]
then
  echo "${POST_SCRIPT}" | base64 -d > /root/postscript.sh
  chmod 700 /root/postscript.sh
  . /root/postscript.sh
fi