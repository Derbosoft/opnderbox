# Configuration d'OPNderbox

L'assistant de première configuration écrit `/etc/opnderbox/config.json` et `/etc/opnderbox/apikey.txt` (lisibles par le seul compte `opnderbox`). Les réglages ci-dessous sont facultatifs ; après une modification : `sudo opnderbox restart`.

| Clé | Par défaut | Rôle |
| --- | --- | --- |
| `opnsense` | (assistant) | adresse de l'interface web d'OPNsense, `https://…` |
| `opnsense_fingerprint` | (assistant) | empreinte SHA-256 du certificat d'OPNsense ; tout autre certificat est refusé |
| `password_hash` | (assistant) | mot de passe de l'interface, haché (`sudo opnderbox password` pour le changer) |
| `port` | 443 (8443 sous Docker) | port d'écoute ; aussi réglable par `OPNDERBOX_PORT` |
| `listen` | `0.0.0.0` | adresse d'écoute |
| `rollback_seconds` | 60 | délai pour confirmer une modification avant le retour automatique |
| `display_name` | nom d'OPNsense | nom affiché en grand dans le bandeau |
| `hide_interfaces` | `[]` | interfaces à ne pas afficher, par leur identifiant OPNsense (`["opt1"]`) |
| `wan_interfaces` | détection | interfaces à traiter comme externes en plus de celles qui ont une passerelle |
| `rule_prefix` | `""` | préfixe de commentaire de vos règles (par exemple `[FW]`) : masqué à l'affichage, ajouté aux règles créées |
| `key_file` | `/etc/opnderbox/apikey.txt` | fichier de la clé API (lignes `key=` et `secret=`) |
| `tls_cert`, `tls_key` | `/etc/opnderbox/tls.crt`, `.key` | certificat de l'interface ; généré (auto-signé, 10 ans) s'il n'existe pas |

Pour utiliser votre propre certificat, remplacez `tls.crt` et `tls.key` (propriétaire `opnderbox`, clé en 0600) puis redémarrez.

## Fichiers de l'état

`/var/lib/opnderbox` garde ce qu'OPNsense ne connaît pas : séparateurs et couleurs de la grille, objets temps, quarantaine, suivi de l'utilisation des règles, politiques enregistrées, et le journal des actions (`journal.log`). Avant chaque application, une copie de l'état précédent y est écrite (`avant-*.csv`, `avant-*.json`).

## Variables d'environnement

`OPNDERBOX_CONFIG` (fichier de configuration), `OPNDERBOX_STATE` (dossier de l'état), `OPNDERBOX_PORT` (port par défaut). Sous systemd, elles se placent dans `/etc/default/opnderbox`.
