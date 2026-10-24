#!/bin/sh
# Installe (ou met à jour) OPNderbox sur Debian, Ubuntu ou un conteneur LXC qui en dérive.
#
#   sudo ./install.sh                 installe, ou met à jour en gardant la configuration
#   sudo ./install.sh --port 8443     écoute sur un autre port que 443
#   sudo ./install.sh --desinstaller  retire le service (garde /etc/opnderbox et /var/lib/opnderbox)
#   sudo ./install.sh --purger        retire tout, configuration et historique compris
#
# À lancer depuis le dossier du dépôt. Seule dépendance : Python 3.9 ou plus (et openssl pour le certificat).
set -eu

PREFIX=/opt/opnderbox
CONF=/etc/opnderbox
STATE=/var/lib/opnderbox
UNIT=/etc/systemd/system/opnderbox.service
CLI=/usr/local/bin/opnderbox
LINK=/usr/sbin/opnderbox      # « pct enter » de Proxmox ne met pas /usr/local/bin dans le PATH
SRC=$(cd "$(dirname "$0")" && pwd)
PORT=""
ACTION=installer

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="${2:-}"; shift 2 ;;
        --port=*) PORT="${1#--port=}"; shift ;;
        --desinstaller) ACTION=desinstaller; shift ;;
        --purger) ACTION=purger; shift ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1 (voir --help)" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "À lancer en root : sudo $0" >&2; exit 1; }

if [ "$ACTION" != installer ]; then
    systemctl disable --now opnderbox 2>/dev/null || true
    rm -f "$UNIT" "$CLI" "$LINK"
    systemctl daemon-reload
    rm -rf "$PREFIX"
    if [ "$ACTION" = purger ]; then
        rm -rf "$CONF" "$STATE" /etc/default/opnderbox
        id opnderbox >/dev/null 2>&1 && userdel opnderbox
        echo "OPNderbox est retiré, configuration comprise."
    else
        echo "OPNderbox est retiré. Configuration gardée dans $CONF et $STATE (--purger pour tout effacer)."
    fi
    exit 0
fi

[ -f "$SRC/opnderbox/server.py" ] || { echo "Lancez ce script depuis le dossier du dépôt OPNderbox." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd est nécessaire (sinon, voir l'installation Docker)." >&2; exit 1; }
case "$PORT" in ""|*[!0-9]*) [ -z "$PORT" ] || { echo "port invalide : $PORT" >&2; exit 2; } ;; esac

# dépendances : Python 3.9+ et openssl (certificat de l'interface)
missing=""
command -v python3 >/dev/null || missing="python3"
command -v openssl >/dev/null || missing="$missing openssl"
if [ -n "$missing" ]; then
    if command -v apt-get >/dev/null; then
        echo "Installation de :$missing"
        apt-get update -qq && apt-get install -y -qq $missing >/dev/null
    else
        echo "Installez d'abord :$missing" >&2; exit 1
    fi
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Python 3.9 ou plus est nécessaire." >&2; exit 1; }

UPDATE=0
[ -f "$PREFIX/server.py" ] && UPDATE=1

# compte de service sans connexion possible
id opnderbox >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin opnderbox

# programme (lecture seule pour le service), configuration et état (au service seul)
rm -rf "$PREFIX.new"
install -d -m 755 "$PREFIX.new" "$PREFIX.new/opnsense"
cp "$SRC/opnderbox/server.py" "$PREFIX.new/"
cp -R "$SRC/opnderbox/static" "$PREFIX.new/"
cp "$SRC/opnsense/"*.php "$PREFIX.new/opnsense/"
chmod -R u=rwX,go=rX "$PREFIX.new"
rm -rf "$PREFIX" && mv "$PREFIX.new" "$PREFIX"
install -d -o opnderbox -g opnderbox -m 700 "$CONF" "$STATE"

if [ -n "$PORT" ]; then
    echo "OPNDERBOX_PORT=$PORT" > /etc/default/opnderbox
fi

install -m 644 "$SRC/packaging/opnderbox.service" "$UNIT"
cat > "$CLI" <<'EOF'
#!/bin/sh
# Commande d'administration d'OPNderbox.
case "${1:-}" in
    setup)    exec runuser -u opnderbox -- python3 /opt/opnderbox/server.py setup ;;
    # saisie en root : le compte du service ne peut pas lire le terminal d'une console root
    password) python3 /opt/opnderbox/server.py password && chown opnderbox:opnderbox /etc/opnderbox/config.json && systemctl restart opnderbox \
                  && echo "Service redémarré : reconnectez-vous avec le nouveau mot de passe." ;;
    status)   exec systemctl status opnderbox ;;
    logs)     exec journalctl -u opnderbox -f ;;
    restart)  exec systemctl restart opnderbox ;;
    *) echo "usage : opnderbox setup | password | status | logs | restart"
       echo "  setup     adresse de l'assistant de première configuration"
       echo "  password  changer le mot de passe de l'interface"
       exit 1 ;;
esac
EOF
chmod 755 "$CLI"
ln -sf "$CLI" "$LINK"

systemctl daemon-reload
systemctl enable opnderbox >/dev/null 2>&1
systemctl restart opnderbox

# attend le démarrage (certificat généré au premier lancement)
i=0
while [ $i -lt 20 ] && ! systemctl is-active --quiet opnderbox; do sleep 0.5; i=$((i + 1)); done
sleep 1
systemctl is-active --quiet opnderbox || { echo "Le service ne démarre pas : journalctl -u opnderbox" >&2; exit 1; }

echo
if [ "$UPDATE" -eq 1 ]; then
    echo "OPNderbox est mis à jour et redémarré."
fi
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
P=$(sed -n 's/^OPNDERBOX_PORT=//p' /etc/default/opnderbox 2>/dev/null || true)
P=${P:-443}
URL="https://${IP:-adresse-du-serveur}$([ "$P" = 443 ] || echo ":$P")/"
if [ -f "$CONF/config.json" ] && grep -q '"opnsense_fingerprint"' "$CONF/config.json"; then
    echo "OPNderbox est en service : $URL"
else
    echo "OPNderbox est installé. Pour le relier à OPNsense, ouvrez dans votre navigateur :"
    echo
    echo "    $(opnderbox setup | sed 's/^Assistant de premiere configuration : //')"
    echo
    echo "(le navigateur signalera un certificat auto-signé : c'est normal, acceptez-le)"
fi
