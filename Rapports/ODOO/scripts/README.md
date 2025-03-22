# Script d'analyse des chemins ODOO

## Description
Ce script bash permet de détecter la présence et l'accessibilité d'une instance ODOO sur un serveur cible en testant les chemins d'accès caractéristiques sur différents ports.

## Fonctionnement
Le script envoie des requêtes HTTP vers trois chemins spécifiques à ODOO (`/web`, `/web/database/selector`, et `/web/login`) sur six ports courants (80, 443, 4848, 8080, 8443, et 12174).

Pour chaque requête, le script affiche uniquement le code de statut HTTP renvoyé par le serveur.

## Utilisation
```bash
./scan_ports_odoo.sh
```

## Interprétation des résultats
- **000** : Pas de réponse ou connexion refusée
- **200** : Accès réussi, la page existe
- **302** : Redirection vers une autre page
- **400** : Requête incorrecte
- **401** : Authentification requise
- **403** : Accès interdit
- **404** : Page non trouvée
- **500** : Erreur interne du serveur

## Exemple de sortie

![](\ODOO\img\script.png)


## Avantages
- Identification rapide des points d'accès ODOO
- Reconnaissance non intrusive
- Détection de redirections et politiques d'accès