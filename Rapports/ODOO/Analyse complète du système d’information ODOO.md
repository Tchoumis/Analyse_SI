# Analyse complète du système d'information ODOO
*Rapport technique de sécurité et architecture*

## Table des matières
1. [Introduction](#introduction)
2. [Découverte et accès à la plateforme ODOO](#découverte-et-accès-à-la-plateforme-odoo)
3. [Analyse technique de l'infrastructure](#analyse-technique-de-linfrastructure)
4. [Découverte des vulnérabilités](#découverte-des-vulnérabilités)
   - [Vulnérabilité Slowloris (CVE-2007-6750)](#vulnérabilité-slowloris-cve-2007-6750)
   - [Vulnérabilité phpMyAdmin (CVE-2005-3299)](#vulnérabilité-phpmyadmin-cve-2005-3299)
   - [Serveur Node.js Express non sécurisé](#serveur-nodejs-express-non-sécurisé)
5. [Analyse des sous-domaines et DNS](#analyse-des-sous-domaines-et-dns)
6. [Tests d'exploitation](#tests-dexploitation)
7. [Analyse des en-têtes HTTP](#analyse-des-en-têtes-http)
8. [Tests d'authentification](#tests-dauthentification)
9. [Recommandations de sécurité](#recommandations-de-sécurité)
10. [Conclusion](#conclusion)

## Introduction

Ce document présente l'analyse détaillée du système d'information ODOO déployé sur l'infrastructure Hidora. L'objectif est d'identifier l'architecture du système, ses composants, les flux d'information et les vulnérabilités potentielles, afin de proposer des mesures correctives pour renforcer sa sécurité.

L'analyse a été réalisée dans le cadre du projet TP7 de Diginamic, conformément aux objectifs définis dans l'énoncé du projet.

## Découverte et accès à la plateforme ODOO

### Historique des observations

Le 13/03/2025, une connexion à l'interface ODOO a été possible avec l'utilisateur "Marc Demo". Cette connexion a révélé une interface presque vide, sans applications ou modules visibles. Quelques liens étaient accessibles, mais l'interface semblait incomplète ou en cours de déploiement.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/1.png)

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/2.png)


Le 14/03/2025, des changements ont été observés sur l'interface. La page de connexion traditionnelle n'était plus accessible, et une redirection vers la page de création de base de données a été mise en place. Ceci indique que le système était probablement en cours de configuration ou de redéploiement.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/3.png)


### Analyse de l'interface ODOO

L'interface observée le 13/03/2025 montre:
- Une authentification fonctionnelle avec l'utilisateur "Marc Demo"
- Une interface minimaliste sans modules activés
- Une page de préférences utilisateur accessible

L'interface observée le 14/03/2025 montre:
- Une redirection vers la page de création de base de données
- Un formulaire demandant:
  - Un mot de passe principal (Master Password)
  - Un nom de base de données
  - Un email
  - Un mot de passe utilisateur
  - Un numéro de téléphone
  - Une sélection de langue et de pays
  - Une option pour inclure des données de démonstration

Cette transition indique une probable réinitialisation ou reconfiguration du système ODOO, possiblement suite à une maintenance ou une mise à jour.

### Analyse de l'outil Wappalyzer
![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/4.png)

L'analyse via Wappalyzer a révélé des informations précieuses sur les technologies utilisées:
- **Sécurité**: Présence de HSTS (HTTP Strict Transport Security)
- **Langages de programmation**: PHP
- **Bibliothèques JavaScript**: jQuery 3.3.1
- **Serveurs web**: OpenResty et Nginx
- **Proxys inversés**: Nginx
- **Frameworks UI**: Bootstrap

Ces informations permettent de mieux comprendre la pile technologique sur laquelle repose le système ODOO.

## Analyse technique de l'infrastructure

### Test de connectivité (ping)

Le test de ping a confirmé que le serveur ODOO est accessible avec un temps de réponse moyen de 68 ms et sans perte de paquets, démontrant une bonne disponibilité du service.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/5.png)


### Scan des ports (nmap)

Le scan nmap a révélé une infrastructure complexe avec de multiples services exposés:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/6.png)


Cette architecture montre:
1. **Multiple couches de serveurs web**: Présence d'OpenResty et Nginx sur différents ports
2. **Séparation des services**: Administration (SSH, FTP) sur des ports non standards (11110, 11111)
3. **Diversité technologique**: Mélange de serveurs web standard et framework JavaScript (Node.js Express)
4. **Infrastructure DNS dédiée**: PowerDNS pour la gestion des noms de domaine

La présence de serveurs web sur plusieurs ports suggère une architecture à plusieurs niveaux, possiblement avec des proxys inverses, ce qui est courant dans les déploiements d'ODOO en entreprise.

## Découverte des vulnérabilités

### Vulnérabilité Slowloris (CVE-2007-6750)

**Description détaillée**:
Slowloris est une attaque de déni de service (DoS) qui fonctionne en établissant de nombreuses connexions partielles au serveur web cible. Contrairement aux attaques DoS traditionnelles qui inondent la cible de trafic, Slowloris utilise des ressources minimales pour maintenir des centaines ou milliers de connexions ouvertes jusqu'à ce que le serveur atteigne sa limite de connexions simultanées.

L'attaque exploite le comportement des serveurs web qui maintiennent une connexion ouverte jusqu'à ce qu'une requête HTTP complète soit reçue ou qu'un délai d'attente soit atteint. Slowloris envoie délibérément des requêtes HTTP partielles et envoie périodiquement des en-têtes HTTP supplémentaires pour empêcher le déclenchement du délai d'attente.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/7.png)


**Détails techniques**:
- **Vecteur CVSS**: (AV:N/AC:L/Au:N/C:N/I:N/A:P)
- **Score NIST**: 5.0 MEDIUM
- **Date de divulgation**: 17/09/2009
- **Impactés**: Principalement Apache HTTP Server 1.x et 2.x avant la version 2.2.15
- **Comportement technique**: L'attaque cible le module mod_reqtimeout qui n'était pas présent dans les versions antérieures d'Apache

**Impact sur l'infrastructure ODOO**:
Cette vulnérabilité peut rendre l'interface ODOO inaccessible, empêchant les utilisateurs légitimes d'accéder au système. Dans un environnement de production, cela pourrait paralyser les opérations commerciales qui dépendent d'ODOO (ventes, achats, gestion de stock, comptabilité).

**Preuve de concept**:
Un test a été réalisé avec l'outil Slowloris sur le port 4848:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/8.png)


Après quelques minutes d'exécution, l'accès au serveur a été perturbé, comme le montre l'erreur "Hmm. We're having trouble finding that site" lors des tentatives de connexion simultanées.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/9.png)


### Vulnérabilité phpMyAdmin (CVE-2005-3299)

**Description détaillée**:
Cette vulnérabilité d'inclusion de fichiers locaux (LFI) affecte phpMyAdmin versions 2.6.4 et 2.6.4-pl1. Elle se produit dans le script grab_globals.lib.php qui permet aux attaquants d'inclure des fichiers locaux arbitraires via le paramètre $_redirect, possiblement en exploitant le tableau subform.

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/10.png)

**Détails techniques**:
- **Vecteur CVSS**: (AV:N/AC:L/Au:N/C:N/I:P/A:N)
- **Score NIST**: 5.0 MEDIUM
- **Date de divulgation**: 2005
- **Impactés**: phpMyAdmin 2.6.4 et 2.6.4-pl1

**Tentatives de vérification**:
Des recherches ont été effectuées pour localiser phpMyAdmin sur différents ports:
```
http://45.66.221.1/phpmyadmin/
http://45.66.221.1:8080/phpmyadmin/
```
![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/11.png)

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/12.png)


Les tests ont montré que phpMyAdmin n'était pas accessible sur les chemins standards, mais le serveur retournait des erreurs 404 (Not Found) ou 500 (Internal Server Error) plutôt que de refuser la connexion, ce qui suggère que le serveur web traite les requêtes mais que l'application n'est pas installée à ces emplacements.

### Serveur Node.js Express non sécurisé

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/13.png)

**Description détaillée**:
Le scan Nikto sur le port 12174 a révélé un serveur Node.js Express présentant de multiples vulnérabilités potentielles:

1. **Absence d'en-têtes de sécurité critiques**:
   - Pas d'en-tête X-Frame-Options (risque de clickjacking)
   - Pas d'en-tête X-Content-Type-Options (risque de MIME sniffing)

2. **Nombreuses vulnérabilités XSS potentielles**:
   - Plus de 200 points d'entrée potentiellement vulnérables aux injections XSS
   - Ces failles permettraient à un attaquant d'exécuter du code JavaScript arbitraire dans le navigateur des utilisateurs

**Implications pour ODOO**:
Si cette application Node.js fait partie de l'écosystème ODOO (par exemple, comme service d'intégration ou API), ces vulnérabilités pourraient être exploitées pour:
- Voler des sessions utilisateurs
- Injecter du contenu malveillant
- Rediriger des utilisateurs vers des sites frauduleux
- Compromettre des données sensibles

**Exploration supplémentaire**:
Une tentative de cartographie des répertoires a été effectuée avec Gobuster:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/14.png)

Cette analyse n'a pas révélé de chemins sensibles accessibles, mais a confirmé que le service répond avec des codes d'erreur 404 pour les ressources inexistantes.

## Analyse des sous-domaines et DNS

L'analyse DNS a permis de découvrir plusieurs sous-domaines associés au serveur principal:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/15.png)


Cette découverte est significative car elle révèle:

1. **Structure multi-tenant**: Les sous-domaines cust111, cust112, etc. suggèrent une architecture multi-tenant où plusieurs clients pourraient partager l'infrastructure ODOO.

2. **Informations sur l'organisation**: Le sous-domaine "indianapolis" pourrait indiquer un lien avec cette localité géographique.

3. **Portail d'information**: Le sous-domaine "info" pourrait héberger de la documentation ou des informations sur la plateforme.

L'existence de ces sous-domaines élargit la surface d'attaque potentielle et nécessite une analyse de sécurité approfondie pour chaque point d'entrée.

## Tests d'exploitation

### Tests sur le serveur FTP (vsftpd 3.0.2)

Des tentatives de connexion au serveur FTP ont été effectuées:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/16.png)


Le serveur FTP n'autorise pas les connexions anonymes, ce qui est une bonne pratique de sécurité. Des tentatives de force brute ont également été réalisées avec Metasploit sans succès:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/17.png)



### Tests sur le serveur SSH (OpenSSH 7.4)

L'énumération des utilisateurs SSH a été tentée avec Metasploit:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/18.png)


Cette analyse a révélé l'existence de l'utilisateur 'root' sur le système, ce qui constitue une information précieuse pour d'éventuelles tentatives d'accès ultérieures.

## Analyse des en-têtes HTTP

L'analyse des en-têtes HTTP a fourni des informations importantes sur la configuration du serveur:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/19.png)


Points notables:
1. **Redirection automatique vers HTTPS**: Bonne pratique de sécurité qui force les connexions chiffrées
2. **Serveur OpenResty**: Variante de Nginx optimisée pour les applications web à haute performance
3. **Cookie HttpOnly**: Protection contre certaines attaques XSS
4. **En-têtes X-Resolver-IP**: Révèlent des informations sur l'infrastructure interne

L'analyse SSL avec `testssl.sh` a montré une configuration robuste:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/20.png)


Détails:
- Support de protocole: 100/100
- Échange de clés: 90/100
- Force de chiffrement: 90/100

Cette configuration SSL solide est un point fort de l'installation.

## Tests d'authentification

Des tentatives d'accès à ODOO ont été effectuées sur différents ports:

![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/img/21.png)


Ces tests n'ont pas retourné de résultats positifs, suggérant que l'interface ODOO n'est plus accessible directement depuis l'extérieur ou a été reconfigurée. Cela pourrait être:
- Une mesure de sécurité délibérée
- Une indication que le système est en cours de maintenance
- Un signe que l'accès a été restreint à certaines adresses IP

## Recommandations de sécurité

Sur la base de l'analyse effectuée, voici les recommandations détaillées pour améliorer la sécurité du système ODOO:

### 1. Protection contre les attaques Slowloris

**Recommandations techniques:**
- **Déployer un WAF (Web Application Firewall)** comme ModSecurity avec des règles spécifiques pour détecter et bloquer les attaques Slowloris
- **Configurer les timeouts du serveur web**:
  ```nginx
  # Pour Nginx/OpenResty
  client_body_timeout 10s;
  client_header_timeout 10s;
  keepalive_timeout 65s;
  send_timeout 10s;
  ```
- **Limiter le nombre de connexions par IP**:
  ```nginx
  # Pour Nginx/OpenResty
  limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
  limit_conn conn_limit_per_ip 20;
  ```
- **Utiliser le module reqtimeout** (pour Apache, si utilisé dans l'infrastructure):
  ```apache
  <IfModule reqtimeout_module>
    RequestReadTimeout header=20-40,MinRate=500
    RequestReadTimeout body=20-40,MinRate=500
  </IfModule>
  ```

### 2. Sécurisation de l'application Node.js Express

**Recommandations techniques:**
- **Ajouter les en-têtes de sécurité manquants**:
  ```javascript
  // Dans l'application Express
  const helmet = require('helmet');
  app.use(helmet()); // Ajoute plusieurs en-têtes de sécurité
  
  // Ou configuration manuelle
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
  });
  ```
  
- **Implémenter une protection contre les XSS**:
  ```javascript
  const xss = require('xss-clean');
  app.use(xss());
  ```
  
- **Échapper correctement les sorties**:
  ```javascript
  const escapeHtml = require('escape-html');
  app.get('/user/:id', (req, res) => {
    const username = getUsername(req.params.id);
    res.send(`<h1>Welcome, ${escapeHtml(username)}</h1>`);
  });
  ```

- **Mettre en place une limite de débit pour les requêtes**:
  ```javascript
  const rateLimit = require('express-rate-limit');
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // 100 requêtes par fenêtre par IP
  });
  app.use(limiter);
  ```

### 3. Sécurisation des sous-domaines

**Recommandations techniques:**
- **Implémenter une politique de sécurité de sous-domaines**:
  - Désactiver les sous-domaines inutilisés
  - Appliquer les mêmes normes de sécurité à tous les sous-domaines
  - Mettre en place une politique CORS stricte pour les API

- **Configuration CORS pour l'API Node.js**:
  ```javascript
  const cors = require('cors');
  app.use(cors({
    origin: ['https://env-5978560-odoo-01.hidora.com'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
  ```

### 4. Renforcement de la sécurité du serveur FTP (vsftpd 3.0.2)

**Recommandations techniques:**
- **Mettre à jour vsftpd** vers la dernière version stable
- **Configurer vsftpd de manière sécurisée**:
  ```
  # /etc/vsftpd.conf
  anonymous_enable=NO
  local_enable=YES
  write_enable=YES
  chroot_local_user=YES
  allow_writeable_chroot=NO
  pam_service_name=vsftpd
  userlist_enable=YES
  userlist_deny=YES
  tcp_wrappers=YES
  ```
- **Remplacer FTP par SFTP** (basé sur SSH) qui est nativement chiffré

### 5. Renforcement de la sécurité du serveur SSH (OpenSSH 7.4)

**Recommandations techniques:**
- **Mettre à jour OpenSSH** vers la dernière version stable
- **Désactiver l'authentification par mot de passe** et utiliser uniquement des clés SSH:
  ```
  # /etc/ssh/sshd_config
  PasswordAuthentication no
  PubkeyAuthentication yes
  PermitRootLogin no
  ```
- **Limiter les utilisateurs autorisés**:
  ```
  # /etc/ssh/sshd_config
  AllowUsers odoo odoo-admin
  ```
- **Configurer des règles de pare-feu** pour limiter l'accès SSH aux adresses IP autorisées

## Modélisation et diagrammes

Pour visualiser l'architecture et les flux d'informations du système ODOO, voici plusieurs diagrammes explicatifs.

### Diagramme d'architecture du système
![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/diagrams/Diagramme%20d%E2%80%99architecture%20du%20syst%C3%A8me.jpeg)




### Diagramme des flux d'information
![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/diagrams/Diagramme%20des%20flux%20d%E2%80%99information.jpeg)



### Diagramme des vulnérabilités identifiées
![](https://github.com/Tchoumis/Analyse_SI/blob/main/Rapports/ODOO/diagrams/Diagramme%20des%20flux%20d%E2%80%99information.jpeg)



## Conclusion

L'analyse du système d'information ODOO a révélé une architecture complexe et diversifiée, avec plusieurs points d'entrée potentiels et certaines vulnérabilités notables.

**Points forts identifiés:**
- Configuration SSL robuste (note A+)
- Serveurs web performants (OpenResty/Nginx)
- FTP et SSH configurés sur des ports non standards
- Redirection HTTP vers HTTPS systématique

**Vulnérabilités et points d'amélioration:**
- Serveur web vulnérable aux attaques Slowloris
- Application Node.js Express manquant d'en-têtes de sécurité essentiels
- Multiples potentielles vulnérabilités XSS dans l'application Node.js
- Surface d'attaque étendue due aux nombreux sous-domaines

Les recommandations formulées dans ce rapport visent à renforcer significativement la sécurité du système ODOO et à améliorer sa résilience face aux attaques. Leur mise en œuvre devrait être priorisée selon la criticité des vulnérabilités identifiées et l'importance stratégique des différents composants du système.

L'analyse suggère également que le système ODOO était possiblement en cours de reconfiguration pendant la période d'analyse, ce qui expliquerait les changements observés dans l'interface et l'accessibilité.
