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

