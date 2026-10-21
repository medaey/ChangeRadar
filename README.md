# ChangeRadar

**Anticiper les changements techniques avant qu’ils ne deviennent des incidents.**

ChangeRadar est un outil de veille technique auto-hébergé qui rapproche les sources publiques de changement (fin de support, bulletins de sécurité, releases) des technologies que vous utilisez. L’objectif : rendre les échéances visibles assez tôt pour préparer une mise à jour, une migration ou une vérification — sans transformer un signal incomplet en certitude.

> **Projet communautaire en évolution.** ChangeRadar aide à prioriser la veille ; il ne remplace ni les bulletins officiels, ni un outil de gestion des vulnérabilités, ni la validation d’un administrateur.

## Pourquoi ce projet ?

Les informations importantes sont dispersées entre les annonces des éditeurs, les catalogues de fin de vie, les CERT et les dépôts de code. Il est facile de rater une date de fin de support ou de découvrir trop tard qu’une technologie doit évoluer.

ChangeRadar propose une vue simple : **sources → technologies suivies → signaux → vérification → action**. Il privilégie la transparence : lorsqu’une source ne permet pas de confirmer qu’une version est affectée, l’interface affiche « À VÉRIFIER » au lieu d’affirmer que l’actif est concerné.


### Surveillance des certificats SSL/TLS

Dans **Sources → Certificats SSL/TLS à surveiller**, ajoute une URL HTTPS ou un nom DNS (port facultatif). À chaque actualisation, ChangeRadar relève le certificat présenté, sa date d’expiration et vérifie séparément si la validation TLS aboutit. Les certificats expirant dans les 30 jours sont signalés comme prioritaires ; ceux expirant dans les 60 jours ou dont la chaîne/identité n’est pas validée demandent une vérification. Les contrôles sont exécutés depuis la machine qui héberge ChangeRadar : les services privés doivent donc être accessibles depuis cet hôte.

**Attention :** le fichier [IANA root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml) décrit les ancres de confiance **DNSSEC** de la zone racine. Ce n’est pas le certificat TLS d’un serveur web et sa validité ne donne pas la date d’expiration d’un certificat HTTPS. Pour surveiller une expiration TLS, ajoute l’URL du service lui-même.

## Fonctionnalités

- **Veille des fins de support** via [endoflife.date](https://endoflife.date/).
- **Bulletins de sécurité** via le flux public du CERT Santé.
- **Suivi de versions GitHub** : releases stables et, si aucune release n’existe, tags présentés comme un signal moins complet.
- **Inventaire technique** : produits, versions, rôles, sites, responsables, licences et échéances de migration déclarées.
- **Événements personnalisés** au format YAML pour les annonces ou changements internes non couverts par les sources automatiques.
- **Traitement des alertes** : filtres, réponses aux questions de vérification et archivage des signalements traités. Les versions d’une technologie peuvent aussi être modifiées directement depuis sa tuile d’alerte, sans changer d’écran.
- **Interface web** utilisable sur ordinateur et mobile, avec stockage local côté serveur.
- **Mode hors-ligne** pour désactiver les appels aux sources externes.

## Démarrage rapide

Prérequis : Python 3.10+ et `pip` pour un lancement local, ou Docker avec Docker Compose.

### Option A — lancement local

Depuis le dossier du projet :

```bash
python -m pip install -r requirements.txt
python server.py
```

Ouvrez ensuite <http://127.0.0.1:8080>.

### Option B — Docker Compose

```bash
docker compose up -d --build
```

Ouvrez <http://127.0.0.1:8080>. Les données persistantes sont stockées dans le volume Docker défini par `docker-compose.yml`.

### Accès et déploiement

Par défaut, le serveur est prévu pour un usage local. Pour un accès distant, configurez un jeton et un reverse proxy HTTPS. Exemple de jeton aléatoire :

```bash
openssl rand -hex 24
```

Configurez la valeur dans `CR_TOKEN` selon votre mode de déploiement. N’exposez pas directement l’interface sur Internet en HTTP. `CR_INSECURE=1` permet de contourner la restriction d’écoute, mais ne doit pas être utilisé comme substitut à une configuration d’accès sécurisée.

## Première configuration

1. Ouvrez **Sources** et actualisez les sources intégrées.
2. Ajoutez les dépôts GitHub publics pertinents, si nécessaire.
3. Dans **Technologies suivies**, sélectionnez une source puis un cycle ou une version disponible. Une version peut être saisie manuellement lorsqu’aucune source ne la publie.
4. Déclarez les technologies, actifs et échéances utiles à votre environnement.
5. Consultez **Veille**, vérifiez les signaux et marquez comme traités les éléments pour lesquels une action a été prise.

Il n’est pas nécessaire de décrire chaque équipement si plusieurs utilisent la même technologie : choisissez un niveau d’inventaire qui reste utile et maintenable pour votre organisation.

## Comment lire les alertes

- **Concerné** : les règles et les informations disponibles indiquent qu’une action est probablement nécessaire.
- **À vérifier** : le rapprochement signale un point à examiner, mais la source ne permet pas de confirmer seule l’impact sur votre version ou votre configuration.
- **Non concerné** : une réponse de vérification enregistrée indique que le signal ne s’applique pas à cet élément.

Les décisions doivent être confirmées avec la source officielle et le contexte réel de l’environnement. En particulier, le flux CERT Santé ne fournit pas systématiquement des versions affectées normalisées : une correspondance par nom ou mot-clé est un point de départ, pas une preuve d’exposition.

## Sources et limites connues

| Source | Usage | Limite importante |
|---|---|---|
| [endoflife.date](https://endoflife.date/) | Cycles de vie et dates de fin de support | Un produit peut être absent du catalogue ou utiliser un identifiant différent de son nom commercial. |
| [CERT Santé](https://cyberveille.esante.gouv.fr/alertes-et-vulnerabilites) | Bulletins de sécurité et alertes | Le rapprochement par mots-clés peut nécessiter une vérification manuelle. |
| GitHub public | Releases, tags et notes de version lorsqu’elles existent | Un tag n’est pas nécessairement une version stable ; les dépôts privés ne sont pas pris en charge sans authentification. |
| Inventaire local | Licences, rôles, sites et dates de migration | Les échéances saisies sont déclaratives et ne sont pas vérifiées automatiquement auprès des éditeurs. |

Autres limites : ChangeRadar n’est pas un scanner réseau, ne détecte pas à lui seul les logiciels réellement installés et ne remplace pas un inventaire automatisé. Il rapproche les données configurées avec des signaux publiquement accessibles.

## Configuration

Les variables suivantes peuvent être utilisées selon le mode de déploiement :

| Variable | Rôle |
|---|---|
| `CR_TOKEN` | Protège l’accès à l’interface par jeton. |
| `CR_INSECURE=1` | Autorise une écoute plus large sans jeton ; à éviter en production. |
| `CR_OFFLINE=1` | Désactive les accès réseau aux sources externes. |
| `CR_REFRESH_HOURS` | Intervalle d’actualisation automatique en heures ; `0` désactive l’actualisation automatique. |
| `CR_EOL_HORIZON_DAYS` | Horizon d’alerte avant une fin de support ; valeur par défaut : 180 jours. |
| `CR_CVE_DAYS` | Période de bulletins CERT Santé examinée ; valeur par défaut : 45 jours. |

Les données locales sont conservées dans `./data` en mode local ou dans le volume Docker prévu par la configuration. L’interface peut réécrire `inventory.yaml` ; les commentaires YAML ne sont alors pas conservés. Sauvegardez les données avant toute modification importante.

## Vérifications et tests

```bash
python -m unittest discover -s tests
python changeradar.py check --today 2026-10-21
```

La date de l’exemple CLI est fixe ; remplacez-la par la date voulue pour vos propres contrôles.

## Contribuer

Les contributions sont les bienvenues, notamment pour améliorer la qualité des sources, les tests, l’accessibilité de l’interface et la documentation.

1. Créez une branche dédiée à votre modification.
2. Ajoutez ou mettez à jour les tests pour les changements de comportement.
3. Lancez `python -m unittest discover -s tests`.
4. Décrivez dans votre pull request le problème résolu, le comportement attendu et les limites éventuelles.

Pour signaler un bug, indiquez les étapes pour le reproduire, le résultat attendu, le résultat observé et les journaux pertinents en retirant au préalable les jetons, secrets et informations internes sensibles.

## Licence

Aucune licence open source n’est déclarée ici tant que le dépôt ne contient pas de fichier `LICENSE`. Si vous souhaitez accepter les contributions et autoriser la réutilisation, ajoutez une licence adaptée au projet avant publication.
