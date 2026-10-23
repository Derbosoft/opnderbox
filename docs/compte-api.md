# Compte API d'OPNsense pour OPNderbox

OPNderbox agit sur OPNsense par son API, avec un compte dédié qui n'a que les droits nécessaires.

## Avec le script (recommandé)

L'assistant de première configuration affiche une commande à coller dans la console d'OPNsense (menu 8, « Shell », ou SSH en root). Elle télécharge [`opnderbox-compte-api.php`](../opnsense/opnderbox-compte-api.php) depuis OPNderbox, vérifie son empreinte SHA-256, puis l'exécute. Vous pouvez aussi copier le script vous-même sur OPNsense :

```sh
php opnderbox-compte-api.php               # crée ou met à jour le compte « opnderbox » et affiche une clé
php opnderbox-compte-api.php --test        # vérifie sans rien enregistrer
php opnderbox-compte-api.php --supprimer   # supprime le compte et ses clés
```

Le compte reçoit un mot de passe aléatoire jamais affiché et aucun shell : il ne sert que par sa clé API. Chaque exécution ajoute une clé ; `--supprimer` les retire toutes.

## À la main

1. *Système > Accès > Utilisateurs* : ajouter un utilisateur `opnderbox` (mot de passe aléatoire, « Générer un mot de passe brouillé »).
2. Dans *Privilèges effectifs*, ajouter les droits ci-dessous.
3. Dans *Clés API*, cliquer sur « + » : OPNsense télécharge un fichier `apikey.txt`. Collez son contenu dans l'assistant d'OPNderbox.

| Droit dans OPNsense | Fonction dans OPNderbox | |
| --- | --- | --- |
| Firewall: Rules [new] | règles de filtrage | indispensable |
| Firewall: Rules | compteurs et catégories des règles | indispensable |
| Firewall: Aliases | objets (lecture) | indispensable |
| Firewall: Alias: Edit | objets (modification) | indispensable |
| Lobby: Dashboard | tableau de bord, état du système | indispensable |
| Diagnostics: Logs: Firewall: Live View | journal de filtrage | indispensable |
| Firewall: NAT: Destination NAT | redirections de ports | |
| Reporting: Traffic | débits des interfaces | |
| Diagnostics: System Health | historiques | |
| Diagnostics: PF Table IP addresses | quarantaine | |
| Diagnostics: Show States | connexions | |
| Diagnostics: ARP Table | machines | |
| Diagnostics: Routing tables | routage | |
| System: Gateways | passerelles | |
| System: Static Routes | routes statiques | |
| Diagnostics: Logs: System | évènements système | |
| Diagnostics: Logs: Gateways | journal de routage | |
| Status: Interfaces | état des interfaces | |
| Status: Services | services | |
| Interfaces: VLAN | VLAN | |
| Interfaces: Assign network ports | interfaces | |
| Services: Dnsmasq DNS/DHCP: Settings | DHCP et DNS | |
| Diagnostics: Configuration History | sauvegardes | |
| System: Firmware | mises à jour | |
| Services: Intrusion Detection | alarmes IDS (si Suricata est utilisé) | |
| CrowdSec | listes noires (si le plugin est installé) | |

Un droit manquant ne bloque que la fonction concernée : son module reste vide et *Système > Connexion à OPNsense* indique ce qui manque.

## Remplacer la clé

Créez une nouvelle clé (script ou *Clés API*), puis remplacez les lignes `key=` et `secret=` de `/etc/opnderbox/apikey.txt` et redémarrez : `sudo opnderbox restart`. Supprimez ensuite l'ancienne clé dans OPNsense.
