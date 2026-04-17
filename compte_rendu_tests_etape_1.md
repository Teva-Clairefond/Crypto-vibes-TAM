# Compte rendu des tests - Etape 1

Date d'execution : 2026-04-14
Heure de fin des tests d'integration : 11:12:59
Projet : `Crypto Vibes`
Perimetre teste : etape 1 uniquement

## Objectif

Verifier que l'implementation actuelle respecte les exigences de l'etape 1 :

- serveur TCP sur port explicite ou par defaut ;
- client TCP sur host/port explicites ou par defaut ;
- prise en charge de plusieurs clients simultanement ;
- diffusion des messages a tous les autres clients connectes ;
- reception en temps reel ;
- gestion propre des deconnexions client et serveur.

## Commandes executees

Verification syntaxique :

```bash
python -m py_compile server.py client.py
```

Validation d'integration :

```bash
python -
```

Le second lancement correspond a un script de test inline qui :

- demarre le serveur sur le port par defaut puis sur un port explicite ;
- ouvre plusieurs connexions clientes ;
- envoie des messages reels sur sockets TCP ;
- verifie la diffusion ;
- ferme des clients ;
- arrete le serveur et verifie la reaction des clients.

## Resultats

### Verification syntaxique

- `PASS` : `server.py` compile correctement.
- `PASS` : `client.py` compile correctement.

### Tests d'integration

1. `PASS` - Serveur sur port par defaut
Le serveur accepte une connexion sur le port `5000`.

2. `PASS` - Serveur sur port CLI
Le serveur accepte une connexion sur le port `5051`.

3. `PASS` - Client avec host et port par defaut
Connexion reussie a `127.0.0.1:5000` sans argument.

4. `PASS` - Client avec host et port explicites
Connexion reussie a `127.0.0.1:5051` avec arguments CLI.

5. `PASS` - Connexion simultanee de plusieurs clients
Trois clients se connectent simultanement au serveur.

6. `PASS` - Diffusion des messages
Un message envoye par un client est recu par tous les autres clients connectes.

7. `PASS` - Absence d'echo chez l'emetteur
Le client qui envoie un message ne recoit pas son propre message en retour.

8. `PASS` - Deconnexion d'un client
Le serveur continue de fonctionner apres la fermeture d'un client.

9. `PASS` - Reception temps reel et arret du serveur
Les clients recoivent le message instantanement puis detectent correctement l'arret du serveur.

Message observe cote clients lors de l'arret du serveur :

```text
Connexion interrompue.
Connexion interrompue.
```

## Bilan global

- Total des tests d'integration executes : `9`
- Tests d'integration reussis : `9`
- Tests d'integration echoues : `0`
- Verification syntaxique : `OK`

Verdict : l'etape 1 est validee sur l'environnement local pour le perimetre demande.

## Fonctionnalites validees

- serveur de chat qui ecoute sur un port passe en parametre ;
- utilisation d'un port par defaut si aucun port n'est fourni ;
- client qui utilise le meme port par defaut si aucun port n'est fourni ;
- connexion a un host explicite ou a `127.0.0.1` par defaut ;
- gestion simultanee de plusieurs clients ;
- diffusion des messages aux autres clients connectes, sans echo chez l'emetteur ;
- echanges en temps reel ;
- gestion propre des deconnexions.

## Hors perimetre

Les fonctionnalites suivantes n'ont pas ete testees ici car elles ne font pas partie de l'etape 1 :

- usernames ;
- rooms ;
- mot de passe ;
- couleurs ;
- timestamps ;
- logs ;
- authentification ;
- chiffrement.
