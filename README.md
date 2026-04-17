# Crypto Vibes

Projet de chat multi-utilisateurs type IRC en Python, réalisé par étapes.

Le projet final doit fournir un serveur et un client de chat sans authentification ni chiffrement, avec des usernames uniques, des rooms, des rooms protégées par mot de passe, des couleurs déterministes et des logs côté serveur.

## Etat actuel

Cette version du dépôt couvre uniquement l'étape 1 :

- serveur TCP multi-clients ;
- client TCP ;
- port configurable en ligne de commande ;
- port par défaut si aucun argument n'est fourni ;
- diffusion des messages à tous les autres clients connectés ;
- gestion propre des déconnexions.

Les fonctionnalités suivantes ne sont pas encore implémentées :

- usernames ;
- rooms ;
- room `general` ;
- mots de passe ;
- couleurs ;
- timestamps ;
- logs ;
- authentification ;
- chiffrement ;
- commandes IRC.

## Structure

- `server.py` : serveur de chat TCP.
- `client.py` : client de chat TCP.

## Prérequis

- Python 3.10 ou supérieur recommandé
- aucune dépendance externe

## Lancement

Important :

- les commandes ci-dessous doivent etre executees depuis le dossier `Crypto-vibes-TAM` ;
- si vous etes dans le dossier parent `29_Crypto_Vibes`, commencez par :

```bash
cd Crypto-vibes-TAM
```

- alternative sans changer de dossier :

```bash
python Crypto-vibes-TAM/server.py 5051
python Crypto-vibes-TAM/client.py 127.0.0.1 5051
```

### Serveur

```bash
python server.py [port]
```

Exemples :

```bash
python server.py
python server.py 5051
```

Comportement :

- si aucun port n'est fourni, le serveur écoute sur le port par défaut `5000` ;
- le serveur écoute sur toutes les interfaces réseau via `0.0.0.0`.

### Client

```bash
python client.py [host] [port]
```

Exemples :

```bash
python client.py
python client.py 127.0.0.1
python client.py 127.0.0.1 5000
python client.py 127.0.0.1 5051
```

Comportement :

- si aucun `host` n'est fourni, le client utilise `127.0.0.1` ;
- si aucun `port` n'est fourni, le client utilise le port par défaut `5000`.

## Utilisation

1. Ouvrir un premier terminal et lancer le serveur.
2. Ouvrir deux ou trois autres terminaux et lancer un client dans chacun.
3. Taper un message dans un client puis valider avec Entrée.
4. Vérifier que le message s'affiche immédiatement chez les autres clients connectés, sans echo chez l'émetteur.
5. Fermer un client et vérifier que le serveur continue à fonctionner.
6. Arrêter le serveur et vérifier que les clients détectent la fermeture de connexion.

## Exemple de session locale

Terminal 1 :

```bash
python server.py
```

Terminal 2 :

```bash
python client.py
```

Terminal 3 :

```bash
python client.py 127.0.0.1 5000
```

## Validation de l'étape 1

Les points suivants ont été vérifiés :

- compilation Python sans erreur avec `python -m py_compile server.py client.py` ;
- démarrage du serveur avec port par défaut ;
- démarrage du serveur avec port explicite ;
- connexion de plusieurs clients simultanés ;
- diffusion des messages aux autres clients connectés, sans echo chez l'émetteur ;
- déconnexion d'un client sans arrêt du serveur ;
- arrêt du serveur avec détection correcte côté client.

## Cahier des charges global

Le projet complet devra à terme respecter les points suivants :

- un serveur de chat capable de gérer plusieurs clients simultanément ;
- un username choisi au démarrage et unique parmi les connexions actives ;
- un système de rooms ;
- certaines rooms protégées par mot de passe ;
- une room par défaut nommée `general` ;
- affichage uniquement des messages de la room courante ;
- ajout d'un timestamp aux messages ;
- attribution d'une couleur déterministe par utilisateur ;
- logs serveur exportés dans un fichier horodaté ;
- affichage distinctif des rooms protégées dans la console.

## Limites de la version actuelle

Cette version est volontairement minimale pour respecter strictement le périmètre de l'étape 1. Elle ne contient aucune logique préparatoire pour les étapes suivantes.
