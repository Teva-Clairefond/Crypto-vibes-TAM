# AGENT

## Objectif

Ce depot contient un projet de chat cryptographique construit par etapes.
Le code doit rester lisible, executable localement et valide a chaque jalon.

## Etat actuel

Les etapes du Jour 1 Partie 1 sont deja implementees :

- serveur TCP multi-clients ;
- usernames uniques parmi les connexions actives ;
- rooms avec `general` par defaut ;
- rooms protegees par mot de passe ;
- filtrage des messages par room ;
- timestamps sur les messages ;
- couleur deterministe par username ;
- logs serveur horodates ;
- affichage distinctif des rooms protegees.

## Regles de travail

- Communiquer en francais, mais garder le code et les identifiants techniques en anglais.
- Avancer strictement etape par etape, sans sauter de jalon fonctionnel.
- Valider chaque etape avant de passer a la suivante.
- Ne pas preparer des abstractions "pour plus tard" sans besoin immediat.
- Privilegier la bibliotheque standard tant que cela reste raisonnable.
- Ajouter des commentaires uniquement quand la logique n'est pas evidente.
- Conserver un comportement simple a tester en local via console.

## Contraintes de depot

- Le coeur du chat reste dans `server.py` et `client.py`.
- Les fichiers de donnees et de configuration ajoutes par les etapes suivantes doivent rester explicites et lisibles.
- Chaque progression significative doit donner lieu a un commit Git separe.

## Priorites des etapes restantes

1. Jour 1 Partie 2 : authentification et stockage MD5 base64.
2. Jour 2 Partie 1 : casse de hash et migration vers un hash moderne sale avec facteur de cout.
3. Jour 2 Partie 2 : derivation et stockage de cles, chiffrement symetrique par bloc.
4. Jour 3 Partie 1 : generation de paire de cles et encapsulation d'une cle symetrique.
5. Jour 3 Partie 2 : E2EE 1-1, annuaire de cles publiques, signature et verification.
