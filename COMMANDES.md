# Commandes Komptia

Référence des opérations Docker (production). Toutes les commandes s'exécutent depuis la racine du repo et passent par `make`. Pour les commandes de développement (`run`, `dev`, `test-unit`, `lint`, etc.), voir `make help`.

> **Sécurité intégrée** : avant chaque action, le Makefile vérifie que Docker tourne et que `.env` existe. Si l'un manque, tu auras un message clair et **rien ne sera modifié**.

---

## Aperçu rapide

| Catégorie | Commande | Effet en une ligne |
|---|---|---|
| **Aide** | `make help` | Liste toutes les commandes |
| **Vie de l'app** | `make up` / `make down` / `make restart` | Démarrer / Arrêter / Redémarrer |
| | `make logs` / `make status` / `make shell` | Suivre / État / Shell interne |
| **Build** | `make build` / `make rebuild` | Construire l'image (avec / sans cache) |
| **Installation** | `make first-run` | **Première fois uniquement** : init complète |
| **Données** | `make backup` | Sauvegarder dans `./backups/` |
| | `make restore FILE=...` | Restaurer un backup |
| | `make reset` | Effacer les données + redémarrer à neuf |

---

## Workflow type

```
┌─────────────────────────────────────────────────────┐
│  PREMIÈRE INSTALLATION (une seule fois)             │
│  cp .env.example .env  →  éditer  →  make first-run │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│  USAGE QUOTIDIEN                                    │
│  make up      ─ démarre                             │
│  make logs    ─ vérifie / debug                     │
│  make status  ─ check rapide                        │
│  make down    ─ arrête (les données restent)        │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│  MAINTENANCE                                        │
│  make backup                       ─ régulier       │
│  git pull && make rebuild && make up  ─ MAJ code    │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│  CAS PARTICULIERS                                   │
│  make restore FILE=...  ─ revenir à un état passé   │
│  make reset             ─ repartir de zéro          │
└─────────────────────────────────────────────────────┘
```

---

# Référence détaillée

## 1. Cycle de vie

### `make up`
**Démarre le container Docker en arrière-plan.**

- Build l'image si elle n'existe pas, sinon utilise l'existante.
- L'app devient accessible sur `http://127.0.0.1:8888`.
- Les données du volume `komptia-data` sont conservées (rien n'est effacé).

```bash
make up
```

**Pré-requis** : `.env` existe et est rempli.

---

### `make down`
**Arrête le container et le supprime.**

- Le **volume Docker reste intact** : aucune donnée n'est perdue.
- Pour redémarrer ensuite : `make up`.

```bash
make down
```

**Quand l'utiliser** : avant une maintenance, pour libérer la RAM, ou juste pour arrêter l'app proprement.

---

### `make restart`
**Enchaîne `down` puis `up`.**

```bash
make restart
```

**Quand l'utiliser** : après avoir modifié `.env` ou `config.yaml` — un simple redémarrage du container ne suffit pas, il faut le re-créer pour qu'il relise les fichiers.

---

### `make logs`
**Affiche les logs en temps réel.**

- Affiche les 200 dernières lignes puis suit en direct.
- `Ctrl+C` pour quitter (le container continue à tourner).

```bash
make logs
```

**Quand l'utiliser** : debug, vérifier un démarrage, surveiller pendant un test.

---

### `make status`
**Affiche l'état du container et un check de santé.**

- Sortie de `docker compose ps` (running / stopped / health).
- Test de l'endpoint `/health` via `curl`.

```bash
make status
```

**Sortie attendue** : `+ Healthcheck OK` si tout va bien.

---

### `make shell`
**Ouvre un shell interactif DANS le container.**

- Tente `bash`, fallback sur `sh` si bash absent.
- Tu te retrouves dans `/opt/komptia` avec accès au code et au volume.

```bash
make shell
```

**Quand l'utiliser** : debug avancé, inspecter la BDD, lancer un script Python à la main.

---

## 2. Build de l'image

### `make build`
**Construit l'image Docker à partir du `Dockerfile`.**

- Utilise le cache Docker (rapide après le premier build).
- Ne démarre pas le container — c'est juste la construction.

```bash
make build
```

---

### `make rebuild`
**Idem `build` mais ignore complètement le cache.**

- Plus lent (refait toutes les couches).
- Force le re-pull de l'image de base et la réinstallation des dépendances.

```bash
make rebuild
```

**Quand l'utiliser** : après modification de `requirements.txt`, ou si `make build` produit un comportement bizarre suspect d'un cache obsolète.

---

## 3. Première installation

### `make first-run`
**À utiliser UNE SEULE FOIS sur une nouvelle installation.**

Enchaîne 4 étapes :

1. **Build + démarre** le container.
2. **Attend** que l'app réponde au healthcheck (jusqu'à 60 secondes).
3. **Initialise la BDD** (tables + migrations) — idempotent.
4. **Crée le premier compte admin** :
   - Soit interactif (demande username, email, mot de passe).
   - Soit auto si tu as rempli `KOMPTIA_ADMIN_USERNAME/EMAIL/PASSWORD` dans `.env`.

```bash
make first-run
```

**Garde-fou** : refuse de tourner si le volume contient déjà des données (impossible d'écraser une install existante par erreur). Si tu veux repartir de zéro sur une install existante, utilise `make reset`.

**Si une étape plante en cours** : tu peux relancer manuellement les étapes restantes :

```bash
make up
docker compose exec app python -m scripts.db_init      # étape 3
docker compose exec app python -m scripts.seed_admin   # étape 4
```

---

## 4. Opérations sur les données

> Cette section couvre les **3 fonctions critiques** : sauvegarder, restaurer, repartir de zéro.

### `make backup`
**Sauvegarde toutes les données dans un fichier `.tar.gz` horodaté.**

#### Ce qui est sauvegardé

Le fichier `./backups/komptia-AAAA-MM-JJ_HH-MM-SS.tar.gz` contient :

| Contenu | Description |
|---|---|
| **Volume Docker complet** | BDD chiffrée SQLite, classeurs `.afz.json`, rapports PDF, logs, `automation_reports/` |
| **`.env`** | Clés de chiffrement et secrets — **sans elles le backup est inutilisable** |
| **`config.yaml`** | Config applicative |
| **`metadata.json`** | Date, taille, version du format |

#### Comment ça marche

- **Par défaut** : stoppe le container avant le snapshot pour garantir la cohérence SQLite (pas de WAL en milieu de commit), puis le redémarre. Downtime ~5 à 30 secondes.
- **Permissions du fichier** : `600` (lisible uniquement par toi).

#### Syntaxe

```bash
make backup                              # Backup standard (stop + snapshot + restart)
make backup HOT=1                        # Backup à chaud (pas de stop, plus rapide)
make backup BACKUP_DIR=/mnt/usb/backups  # Backup dans un autre dossier
```

#### Avertissements

- ⚠️ **Le `.tar.gz` contient les clés** : à stocker en lieu sûr (clé USB chiffrée, coffre, gestionnaire de mots de passe). Si quelqu'un le récupère, il a accès à toute la BDD chiffrée + tous les secrets.
- ⚠️ **`HOT=1` sacrifie l'intégrité** : risque (faible mais réel) de backup incohérent si SQLite écrit pile au moment du snapshot.

#### Refus

`make backup` refuse de s'exécuter si :
- Le volume `komptia-data` n'existe pas (rien à sauvegarder).
- Le volume existe mais est vide.

---

### `make restore FILE=<chemin>`
**Restaure un backup précédent. Remplace TOUTES les données actuelles.**

#### Syntaxe

```bash
make restore FILE=./backups/komptia-2026-04-30_15-30-22.tar.gz
```

#### Étapes

1. **Validation du chemin** `FILE` : refus si caractères dangereux (`"`, `;`, `$`, `` ` ``, etc.) — protection contre l'injection de commandes.
2. **Vérification de l'archive** : intégrité, format, contenu (`data.tar.gz` présent).
3. **Affichage des métadonnées** du backup (date, taille).
4. **Confirmation** : tu dois taper `RESTORE` (en majuscules) pour valider.
5. **Sauvegarde de l'état actuel** : `.env.before-restore-XXX` et `config.yaml.before-restore-XXX` (au cas où tu changes d'avis).
6. **Wipe + restauration** : suppression du volume actuel, recréation, extraction des données du backup.
7. **Restauration de `.env` et `config.yaml`** depuis le backup.
8. **Redémarrage** du container.

#### Cas particuliers

- **Backup sans `.env`** (ancien backup ou `HOT=1` sans `.env` au moment du backup) : un avertissement t'informe que la BDD pourrait ne pas s'ouvrir si la `SQLCIPHER_KEY` actuelle ne correspond pas à celle qui a chiffré la BDD.
- **Backup d'une autre version du code** : restauration techniquement OK, mais des migrations BDD peuvent être nécessaires (rare, car `db_init` est idempotent).

---

### `make reset`
**Efface TOUTES les données et redémarre l'app comme une compta vierge.**

#### Ce qui est effacé

- Le volume Docker `komptia-data` complet : BDD, rapports, logs, classeurs, `automation_reports/`.

#### Ce qui est conservé

- **`.env`** (clés et secrets actuels)
- **`config.yaml`** (config applicative)

> ⚠️ **À LIRE** : « conservé » ne veut pas dire « bonne config pour la prod ». Si ton `.env` actuel contient des **secrets de test ou de dev**, ils restent en place après `reset` — ce qui est **dangereux pour une vraie mise en prod**. Voir [Cas spéciaux](#cas-speciaux) ci-dessous.

#### Étapes

1. **Confirmation** : tape `RESET` (en majuscules).
2. **Backup automatique avant** (sauf `NO_BACKUP=1`).
3. Stop du container, suppression et recréation du volume.
4. Re-build, redémarrage, attente du healthcheck.
5. Re-init BDD + re-création du compte admin (interactif ou via env vars).

#### Syntaxe

```bash
make reset                  # Backup auto avant (recommandé)
make reset NO_BACKUP=1      # Sans backup avant (gain de temps)
```

#### Quand utiliser `make reset`

| Scénario | Approprié ? |
|---|---|
| Tester une migration sur une base propre, sur ma machine de dev | Oui |
| Repartir de zéro après une corruption de données | Oui |
| Préparer une démo / un environnement vierge | Oui |
| **Mettre en prod chez un nouveau client** | **NON** — voir [Cas spéciaux](#cas-speciaux) |

---

## 5. Variables et options globales

| Variable | S'applique à | Effet | Exemple |
|---|---|---|---|
| `BACKUP_DIR` | `backup` | Dossier de destination des backups (défaut `./backups`) | `make backup BACKUP_DIR=/mnt/nas/komptia` |
| `HOT=1` | `backup` | Snapshot sans stopper le container (cohérence non garantie) | `make backup HOT=1` |
| `NO_BACKUP=1` | `reset` | Skip le backup auto avant le wipe | `make reset NO_BACKUP=1` |
| `FILE=...` | `restore` | Chemin du `.tar.gz` à restaurer (obligatoire) | `make restore FILE=./backups/komptia-X.tar.gz` |

---

## Cas spéciaux

### Mettre en prod chez un nouveau client

`make reset` n'est **pas** la bonne porte d'entrée. Il garderait le `.env` actuel (qui peut contenir des secrets de test, faibles, partagés...).

**Procédure correcte** :

```bash
# Sur la machine cible (nouveau serveur / VM client)
git clone <repo-url> /opt/komptia
cd /opt/komptia

# Créer un .env neuf avec des secrets générés ICI
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"  # → SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"  # → SQLCIPHER_KEY
# Éditer .env avec ces valeurs + les credentials Sage / Anthropic / SMTP

make first-run
```

Avantages :
- Repo neuf (pas d'artefacts dev qui traînent).
- `.env` neuf généré sur la machine cible (pas de secrets recyclés).
- Volume Docker neuf (pas d'ancienne BDD résiduelle).

---

### Vérifier qu'un backup est restaurable

Sans toucher à la prod :

```bash
# Sur une autre machine ou un dossier de test
mkdir komptia-test && cd komptia-test
git clone <repo-url> .
cp .env.example .env  # éditer minimalement
make restore FILE=/chemin/vers/komptia-X.tar.gz
make status           # l'app démarre ? le healthcheck passe ?
```

Si oui, le backup est sain. Si non, ne pas se baser sur ce backup.

---

### Mettre à jour le code (nouvelle version)

```bash
git pull          # récupère la nouvelle version (ou re-synchronise le repo client)
make update       # rebuild sans cache + redémarre
```

**Aucune étape de migration manuelle.** Les migrations BDD s'appliquent
**automatiquement au démarrage** (`init_database` → `_run_migrations`, idempotent)
quand `make update` recrée le container. Les données dans le volume Docker
**survivent** (le volume `komptia-data` n'est jamais touché par un rebuild).

> Si le rebuild échoue (ex. nouvelle dépendance KO), l'ancien container reste en
> place → **pas de coupure** ; corrigez puis relancez `make update`.

---

### Récupérer les logs sans le terminal interactif

```bash
docker compose logs --no-color > komptia-$(date +%Y%m%d).log
```

> ⚠️ Les logs peuvent contenir des fragments d'env (en cas de crash). Avant de partager un fichier de log par email / GitHub / Slack, **passer un coup d'oeil** ou redact les chaînes sensibles.

---

## Aide-mémoire

```
make help              ← rappel à l'écran
make first-run         ← UNE SEULE FOIS (nouvelle install)
make up / down         ← cycle de vie
make backup            ← régulier
make restore FILE=...  ← retour en arrière
make reset             ← compta vierge SUR LA MÊME install
```

Pour la mise en prod chez un nouveau client : **PAS `make reset`** — clone neuf + `.env` neuf + `make first-run`.
