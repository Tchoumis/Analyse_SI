# projet Analyser un SI

## Analyse SI - Partie ODOO

### Présentation
Ce dépôt contient les analyses du système d'information dans le cadre du TP7 pour Diginamic (analyses d'un SI existant à partir de son architecture et de son schéma des flux).

### Structure du dépôt

- `README.md` - Ce fichier de présentation
- `Rapports/` - Rapports d'analyses complets
- `Presentation/` - Présentation PowerPoint

### Résultats principaux

L'analyse a porté sur la plateforme ODOO déployée sur Hidora avec l'infrastructure suivante :

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/plat_odoo.png)


#### Vulnérabilités découvertes
- Vulnérabilité Slowloris (CVE-2007-6750)
- Problèmes de sécurité sur Node.js Express (port 12174)
- Absence d'en-têtes de sécurité HTTP importants

#### Tests réalisés
- Scan de ports et services
- Analyse des en-têtes HTTP
- Test de la vulnérabilité Slowloris
- Énumération des sous-domaines DNS

# Site: https://env-9206928-wp02-nosecure.hidora.com/

## Vulnérabilités découvertes

- **Version de WordPress Obsolète (6.6.2)**
- **XML-RPC Activé** (expose à des attaques DDoS et par force brute)
- **Plugins et Thèmes Obsolètes** (W3 Total Cache et Twenty Twenty-Four)
- **Gestion des Cookies Non Avancée**
- **Absence de Sauvegardes de Configuration**
- **Manque d'Outils de Statistiques Avancées**

### Vulnérabilités détectées (plugin W3 Total Cache) :

- **CVE-2024-12365** : SSRF (Server-Side Request Forgery) dans les versions inférieures à 2.8.2.
- **CVE-2024-12008** : Exposition d'informations via des fichiers journaux dans les versions inférieures à 2.8.2.
- **CVE-2024-12006** : Désactivation non authentifiée du plugin et activation/désactivation des extensions dans les versions inférieures à 2.8.2.

### Fonctionnalités spécifiques :

- **XML-RPC activé** : XML-RPC est utilisé pour des attaques comme les attaques par déni de service (DoS).
- **wp-cron activé** : Cette fonctionnalité peut être vulnérable à des attaques DDoS si elle est mal configurée.
- **Fichier readme trouvé** : Le fichier `readme.html` est accessible, ce qui peut fournir des informations sensibles sur le site.

## Tests réalisés

- **Scan de Sécurité**
- **Analyse des Plugins et Thèmes** pour détecter les versions obsolètes et les vulnérabilités associées
- **Vérification des Versions de WordPress et des Composants** pour assurer qu'aucune version vulnérable n'est utilisée
- **Contrôle des Protocoles XML-RPC et HTTPS** pour vérifier les configurations de sécurité
- **Audit des Permissions et des Fichiers Sensibles** pour détecter les mauvaises configurations et les fichiers exposés
- **Audit de la Gestion des Cookies et des Sauvegardes** pour évaluer la conformité avec les bonnes pratiques de sécurité



# Site: https://env-8796793-wp02.hidora.com

## Vulnérabilités découvertes

- **Mots de passe par défaut** (admin/admin) pour l'interface d'administration
- **Accès public à l'interface d'administration** via le port 8443
- **Absence d'authentification à double facteur (2FA)** pour l'interface d'administration
- **Version obsolète de LiteSpeed et WordPress** (6.6.2)
- **Présence de traces Drupal** dans la réponse HTTP, bien que le site soit sous WordPress
- **Fichiers de configuration mal sécurisés** (robots.txt exposant des répertoires sensibles)
- **Exposition de l'API REST de WordPress** (wp-json)

## Tests réalisés

- **Scan de sécurité** pour détecter les vulnérabilités et les configurations incorrectes
- **Analyse des plugins et thèmes** pour identifier les versions obsolètes et les failles de sécurité associées
- **Vérification des versions de WordPress et des composants** afin de garantir qu'aucune version vulnérable n'est utilisée
- **Contrôle des protocoles XML-RPC et HTTPS** pour vérifier les configurations de sécurité
- **Audit des permissions et des fichiers sensibles** pour détecter les mauvaises configurations et les fichiers exposés
- **Audit de la gestion des cookies et des sauvegardes** afin d'évaluer la conformité avec les bonnes pratiques de sécurité

