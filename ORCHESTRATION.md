# ORCHESTRATION

## Strategie

Le projet avance en jalons cumulatifs. Chaque jalon doit :

1. implementer uniquement le perimetre vise ;
2. conserver les fonctionnalites precedentes ;
3. etre valide par compilation et test d'execution ;
4. etre commit puis pousse.

## Sequence de travail

### Jalon 1

Jour 1 Partie 2 : authentification avant acces au chat

- distinction utilisateur connu / nouvel utilisateur ;
- mot de passe confirme a l'inscription ;
- minimum 3 regles de mot de passe ;
- indicateur de force base sur l'entropie ;
- stockage `username:hash_base64_md5` ;
- verification en temps constant.

### Jalon 2

Jour 2 Partie 1 : resistance au hacker marseillais

- ajout de `md5_yolo.txt` et `md5_decrypted.txt` ;
- cassage documente des petits mots de passe ;
- migration vers un hash moderne avec facteur de cout ;
- salage unique >= 96 bits ;
- nouveau format de stockage riche.

### Jalon 3

Jour 2 Partie 2 : chiffrement symetrique

- derivation de cle depuis un secret utilisateur ;
- stockage serveur et client ;
- taille de cle >= 128 bits ;
- chiffrement des messages avant envoi ;
- reutilisation du serveur comme relais.

### Jalon 4

Jour 3 Partie 1 : asymetrique pour l'echange de secret

- paire de cles par client ;
- reutilisation locale des cles existantes ;
- encapsulation d'une cle symetrique ;
- suppression de la dependance au stockage serveur des cles de session.

### Jalon 5

Jour 3 Partie 2 : E2EE 1-1

- annuaire serveur des cles publiques ;
- stockage local des cles publiques connues ;
- cle de session par paire de clients ;
- messages prives chiffres ;
- signature et verification ;
- demonstration de rejet d'un message altere.

## Validation minimale a chaque jalon

- `python -m py_compile server.py client.py`
- scenario d'integration local automatise si possible ;
- verification du non-regression sur les etapes precedentes ;
- commit Git dedie avec message concis.
