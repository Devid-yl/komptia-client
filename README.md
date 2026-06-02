# Komptia

Plateforme web d'automatisation et d'analyse de données comptables, branchée sur une base SQL Server existante.

## Vue d'ensemble

- **Application web** Tornado (Python async) — interface multi-utilisateurs avec rôles et permissions
- **Agent IA Iris** — assistant SQL conversationnel (provider configurable : Anthropic Claude par défaut, autres providers OpenAI-compatibles supportés)
- **Automatisations** — chaînes configurables (extraction → vérification → rapport → diffusion mail)
- **Tableaux de bord** — visualisations et rapports PDF
- **Confidentialité** — BDD locale chiffrée (SQLCipher), anonymiseur local optionnel (Ollama) pour les échanges LLM

## Architecture

```
Navigateur ──HTTPS──► Nginx (reverse-proxy) ──► Docker container
                                                ├─ Tornado (port 8888)
                                                ├─ SQLite chiffré (volume Docker)
                                                └─ pyodbc → SQL Server source
```

**Stack** : Python 3.12 / Tornado / SQLAlchemy 2.0 async / SQLCipher / Anthropic Claude API / pyodbc.

## Pré-requis

- **Docker** ≥ 20.10 et **Docker Compose** v2 (sur la machine cible)
- Accès réseau au serveur SQL Server source (lecture seule)
- Une clé API LLM (Anthropic par défaut)
- Un certificat TLS si exposé hors localhost (Let's Encrypt via certbot recommandé)

C'est tout. Pas besoin d'installer Python, Node, ni les libs système — Docker s'en occupe.

## Installation rapide (première fois)

```bash
# 1. Cloner ce repo sur la machine cible
git clone <url-du-repo> /opt/komptia
cd /opt/komptia

# 2. Configurer l'environnement
cp .env.example .env
# Éditer .env : SECRET_KEY, SQLCIPHER_KEY, SAGE_DB_*, ANTHROPIC_API_KEY, SMTP_*
#   Générer un secret : python3 -c "import secrets; print(secrets.token_hex(32))"

# 3. Build + démarrage + bootstrap admin
make first-run
```

À la dernière étape, `seed_admin` demande interactivement un username / email / mot de passe pour le premier compte administrateur. Pour automatiser (CI, redéploiement scripté), définir dans `.env` :

```
KOMPTIA_ADMIN_USERNAME=admin
KOMPTIA_ADMIN_EMAIL=admin@exemple.local
KOMPTIA_ADMIN_PASSWORD=<mot-de-passe-fort>
```

L'app est ensuite accessible sur `http://127.0.0.1:8888`.

## Variables d'environnement critiques

Voir `.env.example` pour la liste complète. Les plus importantes :

| Variable | Pourquoi |
|---|---|
| `SECRET_KEY` | Signature des sessions. **Modifier déconnecte tous les utilisateurs.** |
| `SQLCIPHER_KEY` | Clé de chiffrement de la BDD locale. **Si perdue ou modifiée, BDD illisible définitivement.** |
| `SAGE_DB_HOST/USER/PASSWORD` | Connexion lecture-seule à la BDD source SQL Server |
| `ANTHROPIC_API_KEY` | Clé du provider LLM principal (peut aussi être saisie via `/admin/ai-config`) |
| `SMTP_HOST/USER/PASSWORD` | Diffusion des rapports par email. Vide = envoi désactivé. |
| `KOMPTIA_ADMIN_*` | (Optionnel) Bootstrap non-interactif du premier admin. À VIDER après le premier démarrage. |

⚠️ **Conserver une copie sûre du `.env`** (gestionnaire de mots de passe, coffre). Sans `SQLCIPHER_KEY`, aucun backup BDD ne peut être restauré.

## Opérations courantes

Toutes les commandes passent par `make` qui orchestre Docker. `make help` liste tout.

### Cycle de vie

```bash
make up              # Démarre le container
make down            # Arrête (les données restent)
make restart         # Stop + start
make logs            # Suivre les logs en direct
make status          # État + healthcheck
make shell           # Shell dans le container (debug)
```

### Sauvegarder / restaurer / repartir de zéro

```bash
make backup                                     # → ./backups/komptia-AAAA-MM-JJ_HH-MM-SS.tar.gz
make restore FILE=./backups/komptia-X.tar.gz    # Restaure (confirmation requise)
make reset                                      # Efface TOUTES les données + bootstrap (backup auto avant)
```

**Détails :**

- `backup` stoppe le container par défaut (cohérence SQLite garantie) puis le redémarre. Pour un backup à chaud sans interruption : `make backup HOT=1` (au risque d'incohérence si SQLite est en plein commit).
- Le `.tar.gz` contient : volume Docker (BDD chiffrée + rapports + logs + classeurs `.afz.json`) + `.env` + `config.yaml` + `metadata.json`. Permissions `600`. **Il contient les clés — stocker en lieu sûr.**
- `restore` demande de taper `RESTORE` pour confirmer, vérifie l'intégrité du tar, puis remplace tout.
- `reset` est destructif. Il fait un backup automatique avant (sauf `make reset NO_BACKUP=1`).

### Si `make first-run` échoue à mi-chemin

`first-run` enchaîne 3 étapes : démarrer le container, init BDD, créer admin. Si une étape plante, relancer manuellement les suivantes :

```bash
make up                                                      # 1. Démarrer
docker compose exec app python -m scripts.db_init            # 2. Init BDD
docker compose exec app python -m scripts.seed_admin         # 3. Créer admin
```

`db_init` est idempotent ; `seed_admin` refuse de créer un 2e admin si un compte admin existe déjà.

### Mise à jour du code

```bash
git pull
make rebuild         # rebuild sans cache (récupère nouvelles dépendances)
make up              # redémarre
```

Les données dans le volume Docker survivent au rebuild.

## Production : reverse-proxy HTTPS

Le container expose le port 8888 **uniquement sur 127.0.0.1** (cf. `docker-compose.yml`). Pour exposer publiquement, mettre Nginx (ou Caddy/Traefik) en reverse-proxy avec TLS.

Une config Nginx d'exemple est fournie dans `deployment/nginx/komptia.conf`. À adapter (server_name, certificats Let's Encrypt) puis :

```bash
sudo cp deployment/nginx/komptia.conf /etc/nginx/sites-available/komptia
sudo ln -s /etc/nginx/sites-available/komptia /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Sécurité

- BDD locale chiffrée (SQLCipher)
- Sessions signées (CSRF, cookies httpOnly)
- Container non-root (utilisateur `komptia` dans l'image)
- Volume des données séparé (résiste aux rebuilds)
- Provider LLM avec niveaux de confidentialité (peek obfusqué, données décontextualisées, anonymiseur local optionnel)

## Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `make up` échoue avec « .env manquant » | `.env.example` non copié | `cp .env.example .env` puis remplir |
| Healthcheck KO après `make up` | Erreur au démarrage de l'app | `make logs` pour voir la trace |
| Connexion SQL Server timeout | Réseau / credentials / TLS legacy | Vérifier `SAGE_DB_*` ; `start.py` charge `openssl_legacy.cnf` si présent |
| Restore impossible (BDD illisible) | `.env` du backup ne correspond pas à la BDD | Restaurer le `.env` qui était dans le backup |

Pour réinitialiser totalement en cas de problème : `make reset` (backup auto avant).

## Licence

Propriétaire.
