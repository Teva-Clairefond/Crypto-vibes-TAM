# AGENTS

## Mission

Ce depot contient un projet de chat crypto en Python construit par etapes. La regle est simple: une seule etape detaillee a la fois, validation complete, puis commit et push avant de passer a la suivante.

Le point de depart de la suite du projet est deja acquis. Les fonctionnalites de base du Jour 1 Partie 1 sont considerees comme stables et ne doivent pas etre refaites sauf regression.

## Equipe

### 1. Planner

Role: decouper la prochaine etape en un ticket unique, testable et sans ambiguity.

Responsabilites:

- lire `sujet_crypto_vibeness.md`, `README.md`, `CONFIG.md` et `ORCHESTRATION.md` avant chaque nouvel etape;
- transformer une grosse partie du sujet en sous-etapes tres petites;
- definir le perimetre exact des fichiers touches;
- fixer les criteres d'acceptation avant toute modification;
- refuser toute anticipation hors perimetre.

Fichiers / sujets de predilection:

- `sujet_crypto_vibeness.md`;
- `ORCHESTRATION.md`;
- `CONFIG.md`;
- `README.md`;
- descriptions d'etapes et comptes rendus.

Ne modifie jamais le code.

### 2. Protocol Implementer

Role: implementer tout ce qui concerne le flux reseau, le protocole client-serveur, l'etat applicatif et l'interface console principale.

Responsabilites:

- modifier `server.py` et `client.py` pour les etapes qui touchent au chat, a l'authentification, aux rooms, aux timestamps, aux couleurs et aux echanges de messages;
- conserver l'existant quand une etape ajoute une seule capacite;
- eviter les abstractions non necessaires;
- garder le code simple, lisible et directement testable en local.

Fichiers / sujets de predilection:

- `server.py`;
- `client.py`.

Ne touche pas aux fichiers de donnees, de configuration ou de documentation sauf demande explicite du Planner.

### 3. Crypto and Storage Implementer

Role: traiter les etapes qui ajoutent les fichiers de stockage, les derivees de cles, les hash, le chiffrement, les signatures et les artefacts cryptographiques durables.

Responsabilites:

- creer ou modifier les fichiers de donnees previsibles par le sujet;
- implemente les formats de stockage stables;
- garder les secrets, les sels, les hashes et les cles dans des emplacements explicites;
- ne pas toucher au protocole reseau tant que ce n'est pas necessaire a la sous-etape courante.

Fichiers / sujets de predilection:

- `this_is_safe.txt`;
- `password_rules.json`;
- `md5_yolo.txt`;
- `md5_decrypted.txt`;
- `user_keys_do_not_steal_plz.txt`;
- `users/`;
- helpers crypto locaux si le projet en cree.

Ne modifie `server.py` ou `client.py` que si le Planner a reserve ces fichiers a cette sous-etape et uniquement pour la portion indispensable.

### 4. Reviewer

Role: verifier chaque diff avant merge interne.

Responsabilites:

- detecter bugs, regressions, ecarts de perimetre, failles de securite, incoherences de format et problemes de compatibilite;
- verifier que la sous-etape courante ne depasse pas le sujet;
- exiger des corrections avant de laisser passer la validation;
- valider la clarte des formats et des messages.

Fichiers / sujets de predilection:

- tous les fichiers modifies par la sous-etape;
- formats de messages, fichiers de stockage, README, comptes rendus, configuration.

Ne fait pas de modification de code sauf si le processus d'iteration le demande explicitement.

### 5. Tester

Role: executer les verifications et produire un resultat factuel.

Responsabilites:

- lancer `python -m py_compile` quand c'est pertinent;
- lancer le serveur et plusieurs clients si la sous-etape le demande;
- verifier les cas nominaux et les cas d'erreur;
- confirmer les non-regressions sur les etapes precedentes;
- noter clairement ce qui passe, ce qui echoue et ce qui reste a corriger.

Fichiers / sujets de predilection:

- scripts de test ad hoc;
- sorties console;
- rapports de validation;
- aucun fichier source en modification normale.

### 6. Release Manager

Role: transformer une sous-etape valide en commit propre et pousse.

Responsabilites:

- verifier que le diff est limite au perimetre du ticket;
- preparer un commit unique par sous-etape validee;
- pousser sur `main` uniquement apres accord du Reviewer et du Tester;
- garder des messages de commit courts et descriptifs.

Fichiers / sujets de predilection:

- Git, pas le code.

## Ordre D Intervention

Pour chaque sous-etape:

1. Planner.
2. Implementer concerne par le perimetre du ticket.
3. Reviewer.
4. Tester.
5. Release Manager.

Si une sous-etape touche plusieurs familles de fichiers, le Planner decoupe encore jusqu'a ce qu'un seul implementer puisse avancer sans overlap.

## Regles Anti-Overlap

- Un ticket, un responsable principal.
- Un fichier ne peut etre edite que par un seul agent a la fois.
- `server.py` et `client.py` ne sont jamais modifies en parallele par deux agents differents.
- Les fichiers de donnees et de configuration ne sont pas modifies pendant qu'un autre agent refactorise le protocole.
- Le Reviewer et le Tester sont en lecture seule.
- Le Release Manager ne modifie pas le code.
- Si un doute existe entre "utile plus tard" et "necessaire maintenant", on coupe.

## Criteres De Sortie D Une Sous-Etape

Une sous-etape est consideree terminee seulement si:

- le perimetre de la sous-etape est respecte;
- les tests essentiels passent;
- le Reviewer ne remonte pas de probleme bloquant;
- le diff reste lisible;
- un commit dedie a ete cree;
- le push a ete effectue si demande.

## Roadmap Detaillee

Le projet doit continuer a partir du point actuel, en detaillant les jalons au lieu de traiter de grosses parties d'un seul bloc.

### Jour 1 - Partie 2 - Authentification

#### Etape 1

Les clients doivent s'authentifier par un mot de passe avant d'entrer dans le chat. Un client non authentifie ne recoit pas les messages et ne peut pas participer.

#### Etape 2

Le serveur doit distinguer un utilisateur deja connu d'un nouvel utilisateur, puis guider chacun vers le bon flux.

#### Etape 3

Le projet doit imposer au moins trois regles de mot de passe et afficher un indicateur simple de force ou d'entropie apres validation.

#### Etape 4

Les mots de passe doivent etre stockes dans `this_is_safe.txt` sous la forme `username:hashed_password`, avec hash MD5 encode en base64 pour cette etape.

#### Etape 5

Les regles de mot de passe doivent vivre dans un fichier de configuration separe, relu au demarrage du serveur.

#### Etape 6

La verification du mot de passe doit etre faite en temps constant.

### Jour 2 - Partie 1 - Le Hacker Marseillais

#### Etape 1

Produire `md5_yolo.txt` et `md5_decrypted.txt` selon l'attaque demandee par le sujet.

#### Etape 2

Migrer le stockage vers un hash moderne avec facteur de cout.

#### Etape 3

Ajouter un sel unique pour chaque mot de passe et un format de stockage explicite et stable.

#### Etape 4

Valider la recuperation et la lecture des anciens et nouveaux formats si la migration le demande.

### Jour 2 - Partie 2 - Chiffrement Symetrique

#### Etape 1

Deriver une cle de chiffrement a partir d'un secret utilisateur via une KDF et un sel dedie.

#### Etape 2

Stocker la cle cote serveur et cote client dans les fichiers predefinis par le sujet.

#### Etape 3

Chiffrer les messages avec un chiffre par bloc avant envoi.

#### Etape 4

Verifier que le relais serveur ne voit plus que des blobs opaques.

### Jour 3 - Partie 1 - Crypto Asymetrique

#### Etape 1

Generer une paire de cles cote client avant connexion ou reutiliser une paire existante.

#### Etape 2

Distribuer ou encapsuler une cle symetrique avec la cle publique du destinataire.

#### Etape 3

Retirer la dependance a un stockage serveur de cles de session.

### Jour 3 - Partie 2 - E2EE 1-1

#### Etape 1

Le serveur doit maintenir un annuaire des cles publiques et le distribuer aux clients.

#### Etape 2

Les clients doivent stocker localement les cles publiques connues.

#### Etape 3

Les messages prives 1-1 doivent utiliser une cle de session par paire de clients.

#### Etape 4

Chaque message doit etre signe par l'expediteur et verifie par le destinataire.

#### Etape 5

Un message altere doit etre rejete de facon visible.

## Politique De Commit

- Un commit par sous-etape validee.
- Message de commit court, factuel et lie a la sous-etape.
- Pas de commit "fourre-tout".
- Pas de push tant que le Reviewer ou le Tester a un point bloquant.

## Rappel De Base

- Communiquer en francais.
- Garder le code et les noms techniques en anglais.
- Utiliser la bibliotheque standard quand c'est raisonnable.
- Ne pas preparer de structures "pour plus tard" si elles ne sont pas necessaires a la sous-etape en cours.
