# CONFIG

## Execution actuelle

- Serveur : `python server.py [port]`
- Client : `python client.py [host] [port]`
- Host client par defaut : `127.0.0.1`
- Port par defaut : `5000`

## Fichiers deja presents

- `server.py` : logique serveur.
- `client.py` : logique client console.
- `README.md` : documentation generale actuelle.
- `compte_rendu_tests_etape_1.md` : ancien compte rendu de la premiere etape.

## Fichiers de donnees prevus par le sujet

- `this_is_safe.txt` : table des mots de passe.
- `password_rules.json` : regles de mot de passe rechargees au demarrage du serveur.
- `md5_yolo.txt` : hash fourni par le sujet.
- `md5_decrypted.txt` : resultat et commande de cassage du hash MD5.
- `user_keys_do_not_steal_plz.txt` : stockage serveur des cles symetriques derivees pour le Jour 2 Partie 2.
- `users/` : stockage local client des cles et materiels cryptographiques.

## Principes de configuration

- Les valeurs modifiables doivent vivre dans des constantes ou fichiers simples.
- Les regles de mot de passe ne doivent pas etre codees en dur si le sujet demande un fichier a part.
- Les artefacts de test et de logs doivent rester separables des fichiers sources.

## Hypotheses techniques

- Python 3.14 est disponible.
- `openssl` et `hashcat` ne sont pas installes par defaut dans l'environnement courant.
- Les etapes cryptographiques devront donc soit utiliser la bibliotheque standard, soit embarquer une implementation locale adaptee au projet pedagogique.
