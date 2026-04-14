# ORCHESTRATION

## Strategie

Le projet avance en sous-etapes cumulatives. Chaque sous-etape doit :

1. implementer uniquement le perimetre vise ;
2. conserver les fonctionnalites precedentes ;
3. etre validee avant de passer a la suivante ;
4. etre commit puis poussee.

## Sequence detaillee

### Jour 1 - Partie 2 : authentification

#### Etape 1

Les clients doivent s'authentifier par un mot de passe pour acceder au chat.
Les clients non-authentifies ne recoivent pas les messages.

#### Etape 2

Cette authentification doit se produire avant l'acces aux rooms, aux commandes
et au chat normal.

#### Etape 3

Le serveur doit distinguer un utilisateur deja connu d'un nouvel utilisateur.

#### Etape 4

Un nouvel utilisateur doit pouvoir creer son compte a la premiere connexion.

#### Etape 5

La creation de compte doit demander une confirmation du mot de passe.

#### Etape 6

Le serveur doit imposer au moins 3 regles de mot de passe.

#### Etape 7

Ces regles doivent vivre dans un fichier separe et etre rechargees a chaque
demarrage du serveur.

#### Etape 8

Si le mot de passe est valide, le client doit recevoir un indicateur simple
de force fonde sur l'entropie.

#### Etape 9

Les mots de passe doivent etre stockes haches avec MD5, encodes en base64,
jamais en clair.

#### Etape 10

Le fichier `this_is_safe.txt` doit contenir une ligne par utilisateur au format
`username:hashed_password`.

#### Etape 11

La verification du mot de passe doit etre faite en temps constant.

#### Etape 12

Validation complete de la partie avec non-regression sur le chat existant.

### Jour 2 - Partie 1 : hacker marseillais

#### Etape 1

Ajouter `md5_yolo.txt` avec le hash fourni par le sujet.

#### Etape 2

Produire `md5_decrypted.txt` avec la commande de brute force demandee et
le message retrouve.

#### Etape 3

Verifier ou documenter clairement la methode pour casser les mots de passe
de 5 caracteres ou moins.

#### Etape 4

Remplacer MD5 par une fonction de hash moderne avec facteur de cout.

#### Etape 5

Ajouter un salt unique par mot de passe de taille minimale 96 bits.

#### Etape 6

Stocker username, algo, facteur de cout, salt et digest dans un format
explicite a separateurs stables.

#### Etape 7

Faire evoluer inscription et connexion vers ce nouveau format de stockage.

#### Etape 8

Valider le nouveau stockage et son integration au login.

### Jour 2 - Partie 2 : chiffrement symetrique

#### Etape 1

Deriver une cle de chiffrement depuis un secret saisi par l'utilisateur.

#### Etape 2

Utiliser une KDF avec un sel dedie par utilisateur.

#### Etape 3

Garantir une taille de cle d'au moins 128 bits.

#### Etape 4

Stocker cote serveur la cle et son sel dans `user_keys_do_not_steal_plz.txt`.

#### Etape 5

Stocker cote client le materiel correspondant dans un repertoire local.

#### Etape 6

Introduire un chiffrement symetrique par bloc pour les messages.

#### Etape 7

Le client doit chiffrer ses messages avant envoi.

#### Etape 8

Le destinataire doit dechiffrer les messages recus et continuer a afficher
le resultat de facon compatible avec les etapes precedentes.

#### Etape 9

Validation du chiffrement des conversations et des non-regressions.

### Jour 3 - Partie 1 : asymetrique

#### Etape 1

Le client doit generer une paire de cles asymetriques avant connexion.

#### Etape 2

Une paire existante doit etre reutilisee si elle est deja presente localement.

#### Etape 3

Les cles doivent etre stockees dans deux fichiers locaux suffixes `.priv`
et `.pub`.

#### Etape 4

La crypto asymetrique doit servir a encapsuler ou echanger une cle symetrique.

#### Etape 5

Le chiffrement symetrique existant doit etre rebranche sur cette cle echangee.

#### Etape 6

Le fonctionnement ne doit plus dependre d'un stockage serveur de cles de session.

#### Etape 7

Validation de l'echange de secret et du chat chiffre apres echange.

### Jour 3 - Partie 2 : E2EE 1-1

#### Etape 1

Chaque client doit envoyer sa cle publique au serveur a la connexion.

#### Etape 2

Le serveur doit maintenir un annuaire `{username: public_key}`.

#### Etape 3

Le serveur doit distribuer cet annuaire ou les cles publiques necessaires
aux autres clients.

#### Etape 4

Chaque client doit stocker localement les cles publiques des correspondants connus.

#### Etape 5

Une cle de session symetrique doit etre etablie par paire de clients.

#### Etape 6

Le serveur ne doit relayer que le blob chiffre correspondant a cet echange.

#### Etape 7

Les messages prives 1-a-1 doivent etre chiffres avec cette cle de session.

#### Etape 8

Les logs serveur ne doivent contenir que du contenu chiffre pour ces messages.

#### Etape 9

Chaque message prive doit etre signe par l'expediteur.

#### Etape 10

Le destinataire doit verifier la signature et rejeter tout message altere.

#### Etape 11

Un test d'alteration manuelle d'un octet en transit doit demontrer le rejet.

#### Etape 12

Validation finale de l'E2EE 1-1 et des non-regressions globales.

## Validation minimale a chaque sous-etape

- `python -m py_compile server.py client.py`
- scenario d'integration local automatise si possible ;
- verification de non-regression sur les etapes precedentes ;
- revue du diff avant commit ;
- commit Git dedie avec message concis.
