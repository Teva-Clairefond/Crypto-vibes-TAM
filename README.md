# Crypto Vibes

Projet de chat multi-utilisateurs en Python realise par etapes, avec progression depuis un chat TCP simple jusqu'a un chat avec authentification, chiffrement de transport et messages prives E2EE signes. Ce projet a été réalisé avec l'aide de l'intelligence artificielle.

## Fonctionnalites

- serveur TCP multi-clients ;
- usernames uniques sur les connexions actives ;
- authentification utilisateur avec enregistrement et reconnexion ;
- regles de mots de passe chargees depuis `password_rules.json` ;
- stockage des mots de passe dans `this_is_safe.txt` avec `scrypt` et migration des anciens formats ;
- rooms avec `general` par defaut ;
- rooms protegees par mot de passe ;
- affichage distinctif des rooms protegees ;
- timestamps sur les messages de chat ;
- couleur deterministe par username ;
- logs serveur horodates dans `log_YYYY-MM-DD_HH-MM-SS.txt` ;
- paire RSA locale par utilisateur ;
- chiffrement du transport client-serveur par cle de session ;
- annuaire des cles publiques des utilisateurs authentifies ;
- stockage local des cles publiques connues ;
- messages prives 1-1 chiffrés de bout en bout ;
- signature et verification des messages prives ;
- rejet visible des messages prives alteres.

## Structure

- `server.py` : serveur principal.
- `client.py` : client console.
- `crypto_utils.py` : chiffrement symetrique et utilitaires bloc/KDF.
- `asymmetric_utils.py` : utilitaires RSA.
- `password_rules.json` : regles de mot de passe.
- `this_is_safe.txt` : base des mots de passe.
- `md5_yolo.txt` et `md5_decrypted.txt` : artefacts de la partie hash.

## Prerequis

- Python 3.10 ou plus recent recommande.
- dependance Python :

```bash
pip install -r requirements.txt
```

## Lancement

Depuis le dossier `Crypto-vibes-TAM` :

```bash
python server.py [port]
python client.py [host] [port]
```

Exemples :

```bash
python server.py
python server.py 5051
python client.py
python client.py 127.0.0.1 5051
```

Valeurs par defaut :

- serveur : port `5000`
- client : host `127.0.0.1`, port `5000`

## Utilisation

Au premier lancement avec un username inconnu :

1. saisir un username ;
2. creer un mot de passe conforme aux regles ;
3. le client genere ou recharge sa paire `identity.priv` / `identity.pub`.

Aux lancements suivants :

1. saisir le meme username ;
2. saisir le mot de passe ;
3. la connexion reprend avec la meme identite locale.

## Commandes

Commandes de chat de room :

- `/create nom_room`
- `/create nom_room motdepasse`
- `/join nom_room`
- `/join nom_room motdepasse`
- `/room`

Commandes crypto cote client :

- `/pubkey username` : affiche la cle publique locale connue pour ce contact.
- `/dm username message` : envoie un message prive chiffre de bout en bout et signe.

Les messages de chat classiques restent limites a la room courante. Les messages `/dm` sont hors-room et passent par le relais serveur sous forme opaque.

## Fichiers generes

- `log_*.txt` : logs serveur par execution.
- `users/<username_encode>/identity.priv` : cle privee RSA locale.
- `users/<username_encode>/identity.pub` : cle publique RSA locale.
- `users/<username_encode>/peers/*.pub` : cles publiques connues et pinnees localement.

## Notes importantes

- Le projet est pedagogique et n'est pas destine a la production.
- Les messages prives 1-1 sont signes et verifies cote client.
- Les cles publiques deja apprises sont conservees localement et ne sont pas remplacees silencieusement.
- Les logs serveur des messages prives ne contiennent pas le plaintext.

## Validation

Des validations ont ete executees au fil des etapes, notamment :

- compilation `python -m py_compile server.py client.py crypto_utils.py asymmetric_utils.py` ;
- authentification, migration de hash et verification en temps constant ;
- key exchange RSA de transport ;
- annuaire de cles publiques et persistance locale ;
- DM E2EE avec cle de session par paire ;
- verification de signature et rejet d'un message altere.
