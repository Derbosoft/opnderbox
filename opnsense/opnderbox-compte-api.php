<?php
/*
 * OPNderbox : crée sur OPNsense le compte API limité dont OPNderbox a besoin.
 *
 * À lancer sur OPNsense, en root (console : option 8 « Shell », ou SSH) :
 *     php opnderbox-compte-api.php               crée (ou met à jour) le compte « opnderbox » et affiche une clé API
 *     php opnderbox-compte-api.php --test        vérifie sans rien enregistrer
 *     php opnderbox-compte-api.php --supprimer   supprime le compte et ses clés
 *
 * Le compte n'a que les droits listés ci-dessous (aucun accès à l'interface web ni au shell).
 * La clé ne s'affiche qu'une fois : collez les lignes key=... et secret=... dans l'assistant d'OPNderbox.
 * Une nouvelle exécution ajoute une nouvelle clé (les anciennes restent valables jusqu'à --supprimer).
 */

require_once("config.inc");
require_once("util.inc");
require_once("/usr/local/opnsense/mvc/script/load_phalcon.php");

use OPNsense\Auth\User;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;

$NAME = 'opnderbox';
$PRIVS = [
    // indispensables
    'page-filter-api',                          // Firewall: Rules [new]
    'page-firewall-rules',                      // Firewall: Rules (compteurs, catégories)
    'page-firewall-aliases',                    // Firewall: Aliases
    'page-firewall-alias-edit',                 // Firewall: Alias: Edit
    'page-system-login-logout',                 // Lobby: Dashboard (état du système)
    'page-diagnostics-logs-firewall-dynamic',   // Diagnostics: Logs: Firewall: Live View
    // fonctions complémentaires
    'page-firewall-nat-portforward-edit',       // Firewall: NAT: Destination NAT
    'page-status-trafficgraph',                 // Reporting: Traffic
    'page-diagnostics-health',                  // Diagnostics: System Health
    'page-diagnostics-tables',                  // Diagnostics: PF Table IP addresses (quarantaine)
    'page-diagnostics-showstates',              // Diagnostics: Show States
    'page-diagnostics-arptable',                // Diagnostics: ARP Table
    'page-diagnostics-routingtables',           // Diagnostics: Routing tables
    'page-system-gateways',                     // System: Gateways
    'page-system-staticroutes',                 // System: Static Routes
    'page-diagnostics-logs-system',             // Diagnostics: Logs: System
    'page-diagnostics-logs-gateways',           // Diagnostics: Logs: Gateways
    'page-status-interfaces',                   // Status: Interfaces
    'page-status-services',                     // Status: Services
    'page-interfaces-vlan-edit',                // Interfaces: VLAN
    'page-interfaces-assignnetworkports',       // Interfaces: Assign network ports
    'page-services-dnsforwarder',               // Services: Dnsmasq DNS/DHCP: Settings
    'page-diagnostics-configurationhistory',    // Diagnostics: Configuration History
    'page-system-firmware-manualupdate',        // System: Firmware
    'page-services-ids',                        // Services: Intrusion Detection
    'page-user-crowdsec',                       // CrowdSec (si le plugin est installé)
];

$mode = $argv[1] ?? '';
if (!in_array($mode, ['', '--test', '--supprimer'], true)) {
    fwrite(STDERR, "usage : php {$argv[0]} [--test | --supprimer]\n");
    exit(2);
}
if (function_exists('posix_getuid') && posix_getuid() !== 0) {
    fwrite(STDERR, "à lancer en root (console d'OPNsense, option 8)\n");
    exit(1);
}

// on ne garde que les droits connus de ce pare-feu (un plugin absent n'a pas de droit)
$known = array_keys((new ACL())->getPrivList());
$privs = array_values(array_intersect($PRIVS, $known));
$absent = array_values(array_diff($PRIVS, $known));

Config::getInstance()->lock();
$mdl = new User();
$uuid = null;
foreach ($mdl->user->iterateItems() as $key => $node) {
    if ((string)$node->name === $NAME) {
        $uuid = $key;
    }
}

if ($mode === '--supprimer') {
    if ($uuid === null) {
        echo "Aucun compte « {$NAME} » : rien à supprimer.\n";
        exit(0);
    }
    $mdl->user->del($uuid);
    $mdl->serializeToConfig();
    Config::getInstance()->save();
    echo "Compte « {$NAME} » et ses clés API supprimés.\n";
    exit(0);
}

$isNew = $uuid === null;
$user = $isNew ? $mdl->user->Add() : $mdl->user->$uuid;
if ($isNew) {
    $user->name = $NAME;
    $user->descr = 'OPNderbox : console d\'administration (compte API, droits limités)';
    $user->scope = 'user';
    // mot de passe aléatoire jamais affiché : le compte ne sert que par sa clé API
    $user->password = $mdl->generatePasswordHash(base64_encode(random_bytes(36)));
    $user->pwd_changed_at = microtime(true);
}
$user->priv = implode(',', $privs);
$key = $user->apikeys->add();

$errors = $mdl->performValidation();
if (count($errors)) {
    foreach ($errors as $e) {
        fwrite(STDERR, 'ERREUR ' . $e->getField() . ' : ' . $e->getMessage() . "\n");
    }
    exit(1);
}

echo ($isNew ? "Compte « {$NAME} » à créer" : "Compte « {$NAME} » existant : droits mis à jour") . ", " . count($privs) . " droits.\n";
if ($absent) {
    echo "Droits absents de ce pare-feu (extensions non installées) : " . implode(', ', $absent) . "\n";
}
if ($mode === '--test') {
    echo "Identifiant système prévu : " . ((string)$user->uid ?: "(attribué à l'enregistrement)") . "\n";
    echo "Test seulement : rien n'a été enregistré.\n";
    exit(0);
}

$mdl->serializeToConfig();
Config::getInstance()->save();

echo "\nClé API créée. À coller dans l'assistant d'OPNderbox (elle ne sera plus affichée) :\n\n";
echo "key=" . $key['key'] . "\n";
echo "secret=" . $key['secret'] . "\n\n";
