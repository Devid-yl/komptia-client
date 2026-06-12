# =================================================
# Makefile - Komptia v2.0
# Commandes de développement et déploiement
# =================================================

.PHONY: help install dev run test test-js lint format clean css \
        check-docker check-compose check-env check-file \
        build rebuild up down restart logs status container \
        first-run backup restore reset _wait-healthy _mark-initialized \
        _write-keycheck _scrub-admin-password keycheck-refresh \
        prefetch-models _prefetch-models \
        llm-local-up llm-local-down llm-local-pull \
        llm-local-enable llm-local-disable _prefetch-llm-local \
        sync-from-appfazia generate-client-repo \
        production-setup deploy-config cert-renew-timer lock

# Variables
PYTHON := python3
VENV := venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
BLACK := $(VENV)/bin/black
FLAKE8 := $(VENV)/bin/flake8
MYPY := $(VENV)/bin/mypy

# Couleurs pour l'affichage
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# Variables Docker (production)
COMPOSE        := docker compose
SERVICE        := app
VOLUME         := komptia-data
# Modèle Ollama par défaut pré-téléchargé à l'activation du LLM local. Défaut de
# COUCHE DÉPLOIEMENT (pas dans le code métier — règle GÉNÉRICITÉ) ; surchargeable :
# `make llm-local-enable OLLAMA_DEFAULT_MODEL=qwen2.5:3b`.
OLLAMA_DEFAULT_MODEL ?= llama3.2:3b
BACKUP_DIR     ?= ./backups
# Image-outil minimale pour inspecter/tar le volume (backup/restore/checks).
# PINNÉE (pas `alpine` = `:latest` flottant) → reproductible + cible de pré-chargement
# CLAIRE pour un serveur ISOLÉ : `docker pull alpine:3` (sur machine connectée) →
# `docker save alpine:3 | ...` → `docker load` côté serveur, en plus de l'image de base
# du build. Surchargeable : make backup ALPINE_IMG=alpine:3.20
ALPINE_IMG     ?= alpine:3
TIMESTAMP      := $(shell date +"%Y-%m-%d_%H-%M-%S")
HEALTH_URL     := http://127.0.0.1:8888/health
# Délai max d'attente du healthcheck au démarrage. 180s (et non 60) : le 1er boot
# d'une GROSSE BDD applique des migrations qui peuvent durer > 1 min (ex. DROP
# COLUMN sur ~29M lignes ≈ 99s) → 60s déclarait un faux échec en prod alors que
# l'app finissait juste de migrer. Surchargeable : make up HEALTH_TIMEOUT=300.
HEALTH_TIMEOUT := 180

help: ## Affiche cette aide
	@echo "$(BLUE)Komptia v2.0 - Commandes disponibles$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_./-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# =================================================
# Installation
# =================================================

venv: ## Crée l'environnement virtuel
	$(PYTHON) -m venv $(VENV)
	@echo "$(GREEN)✓ Environnement virtuel créé$(RESET)"

install: venv ## Installe les dépendances
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Dépendances installées$(RESET)"

install-dev: install ## Installe les dépendances de développement
	$(PIP) install -r requirements-dev.txt 2>/dev/null || $(PIP) install pytest pytest-asyncio pytest-cov black flake8 mypy
	@echo "$(GREEN)✓ Dépendances dev installées$(RESET)"

# =================================================
# Développement
# =================================================

run: ## Lance le serveur de développement
	@echo "$(BLUE)🚀 Démarrage Komptia...$(RESET)"
	$(VENV)/bin/python -m app.main --debug=true

run-prod: ## Lance le serveur en mode production
	$(VENV)/bin/python -m app.main --debug=false

dev: ## Lance avec auto-reload
	DEBUG=true $(VENV)/bin/python -m app.main --debug=true

shell: ## Lance un shell Python avec le contexte de l'app
	$(VENV)/bin/python -c "from app.config import config; print('Config loaded'); import code; code.interact(local=locals())"

# =================================================
# Tests
# =================================================

test: ## Lance tous les tests
	$(PYTEST) tests/ -v

test-unit: ## Lance les tests unitaires (Python + gardes JS de parité)
	$(PYTEST) tests/unit/ -v
	@$(MAKE) --no-print-directory test-js

test-js: ## Gardes JS (Node, sans dépendance) — parité pagination front↔back + grille
	@command -v node >/dev/null 2>&1 || { echo "⚠ node introuvable — tests JS sautés"; exit 0; }
	node tests/js/test_pagination.mjs
	node tests/js/test_grid_column_sum.mjs
	node tests/js/test_grid_sql_tabs.mjs
	node tests/js/test_grid_store.mjs
	node tests/js/test_grid_persist_tiers.mjs
	node tests/js/test_grid_scripts_partial.mjs
	node tests/js/test_external_sheets_sql_preserved.mjs
	node tests/js/test_dag_version_conflict_serialize.mjs
	node tests/js/test_automation_version_etag_guard.mjs
	node tests/js/test_dag_activate_button_route.mjs
	node tests/js/test_datastore_sort.mjs
	node tests/js/test_format_helpers.mjs
	node tests/js/test_read_json.mjs
	node tests/js/test_onboarding_icons_ssot.mjs
	node tests/js/test_onboarding_no_duplicate_modal.mjs

test-integration: ## Lance les tests d'intégration
	$(PYTEST) tests/integration/ -v

test-cross-schema: ## T18 — Prouve la généricité du pipeline NL→SQL sur 3 schémas BDD (Sage Coala-like / SQLite mock / Chinook). Aucun LLM appelé, < 1s.
	$(PYTEST) -m cross_schema tests/integration/test_cross_schema.py -v --strict-markers

test-copilot-e2e: ## Test e2e copilot_agent (vrai LLM, ~$$0.20, ~2min)
	@echo "$(YELLOW)⚠ Appel LLM réel — nécessite ANTHROPIC_API_KEY$(RESET)"
	$(PYTEST) tests/integration/test_copilot_agent_e2e_ratio2.py -v

test-copilot-e2e-stress: ## Test e2e copilot_agent sur classeur lourd+bruité (vrai LLM, peut durer 30-90min)
	@echo "$(YELLOW)⚠ Appel LLM réel — classeur 13 tabs + bruit — nécessite provider configuré$(RESET)"
	@echo "$(YELLOW)⚠ Sonnet 4.6 thinking + 25-30 tours d'agent + tools : 30-90min$(RESET)"
	@echo "$(YELLOW)⚠ Coût ~$$0.30-1.00 selon thinking budget + nombre de tours$(RESET)"
	$(PYTEST) tests/integration/test_copilot_agent_e2e_stress_noisy.py -v --timeout=7200

test-copilot-e2e-stress-anon: ## Idem stress mais APPLIQUE l'auto-anonymisation (mesure l'impact réel sur le score)
	@echo "$(YELLOW)⚠ MODE APPLY_ANON=1 — traduction bidirectionnelle mise à l'épreuve$(RESET)"
	@echo "$(YELLOW)⚠ Pré-requis : LLM local configuré + démarré via /admin/ai-config$(RESET)"
	@echo "$(YELLOW)⚠ Comparer au baseline 'make test-copilot-e2e-stress' pour voir l'impact$(RESET)"
	STRESS_NOISY_APPLY_ANON=1 $(PYTEST) tests/integration/test_copilot_agent_e2e_stress_noisy.py -v --timeout=7200

test-cov: ## Lance les tests avec couverture
	$(PYTEST) tests/ --cov=app --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)✓ Rapport de couverture: htmlcov/index.html$(RESET)"

# =================================================
# Qualité de code
# =================================================

lint: ## Vérifie le style du code
	$(FLAKE8) app/ tests/ --max-line-length=100 --ignore=E501,W503
	@echo "$(GREEN)✓ Lint OK$(RESET)"

format: ## Formate le code avec Black
	$(BLACK) app/ tests/ --line-length=100
	@echo "$(GREEN)✓ Code formaté$(RESET)"

format-check: ## Vérifie le formatage sans modifier
	$(BLACK) app/ tests/ --check --line-length=100

typecheck: ## Vérifie les types avec MyPy
	$(MYPY) app/ --ignore-missing-imports
	@echo "$(GREEN)✓ Types OK$(RESET)"

check: lint format-check typecheck ## Lance toutes les vérifications
	@echo "$(GREEN)✓ Toutes les vérifications passées$(RESET)"

# =================================================
# Assets
# =================================================

css: ## Construit le CSS Tailwind
	npx tailwindcss -i static/css/tailwind-input.css -o static/css/tailwind.min.css --minify
	@echo "$(GREEN)✓ CSS Tailwind construit$(RESET)"

guides: ## Génère les guides d'utilisation PDF par rôle (docs/guides/) — requiert pandoc + weasyprint
	$(VENV)/bin/python scripts/build_guides.py
	@echo "$(GREEN)✓ Guides PDF générés (docs/guides/) — servis dans /settings → Aide$(RESET)"
	@echo "$(YELLOW)Note : à lancer côté DEV avant l'export/build prod. Le Dockerfile embarque docs/guides/*.pdf ;$(RESET)"
	@echo "$(YELLOW)       un build sans ces PDF échoue volontairement (fail-loud) plutôt que de livrer une section Aide vide.$(RESET)"

doc-technique: ## Génère docs/komptia_documentation_technique.{html,pdf} (Mermaid pré-rendu) — requiert pandoc + weasyprint + mmdc
	$(VENV)/bin/python scripts/build_doc_technique.py
	@echo "$(GREEN)✓ Doc technique régénérée (diagrammes Mermaid pré-rendus en SVG)$(RESET)"
	@echo "$(YELLOW)Note : requiert Node + @mermaid-js/mermaid-cli (npm i -g, ou npx au 1er run).$(RESET)"

# =================================================
# Base de données
# =================================================

venv-check:
	@test -x $(VENV)/bin/python || ( \
		echo "$(YELLOW)⚠ venv absent ou cassé : $(VENV)/bin/python introuvable$(RESET)" ; \
		echo "$(YELLOW)  Lancez d'abord: make install$(RESET)" ; \
		exit 1 \
	)

db-init: venv-check ## Initialise la base de données (tables SQLAlchemy + migrations idempotentes)
	$(VENV)/bin/python -m scripts.db_init
	@echo "$(GREEN)✓ Base de données initialisée$(RESET)"

db-seed-admin: venv-check ## Crée le premier compte administrateur (idempotent — refuse si admin existe déjà)
	$(VENV)/bin/python -m scripts.seed_admin
	@echo "$(GREEN)✓ Compte administrateur prêt$(RESET)"

db-bootstrap: db-init db-seed-admin ## Init complet : tables + premier admin (commande de première installation)
	@echo "$(GREEN)✓ Komptia est prêt à l'emploi$(RESET)"

# Pas de cible de migration manuelle : les migrations de schéma sont idempotentes
# et s'appliquent AU DÉMARRAGE du conteneur (init_database -> _run_migrations) ;
# `make db-init` les applique aussi explicitement. v2.0 n'utilise PAS Alembic
# (absent des requirements), d'où le retrait des cibles mortes db-migrate /
# db-revision qui appelaient un binaire `alembic` inexistant.

# =================================================
# Nettoyage
# =================================================

clean: ## Nettoie les fichiers temporaires
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Nettoyage terminé$(RESET)"

clean-all: clean ## Nettoie tout (inclus venv)
	rm -rf $(VENV)
	rm -rf data/logs/*
	@echo "$(GREEN)✓ Nettoyage complet terminé$(RESET)"

# =====================================================================
# PRODUCTION — Docker
# =====================================================================
# Toutes les ops passent par `docker compose`. Aucune dépendance Python
# locale requise — Docker gère tout.
# Voir COMMANDES.md pour la doc détaillée.
# =====================================================================

# --- Pré-requis ------------------------------------------------------

check-docker:
	@docker version >/dev/null 2>&1 || { \
	  printf "$(RED)X Docker n'est pas démarré ou non installé.$(RESET)\n"; \
	  printf "   Lancez Docker Desktop, puis réessayez.\n"; \
	  exit 1; \
	}

check-compose: check-docker
	@$(COMPOSE) version >/dev/null 2>&1 || { \
	  printf "$(RED)X 'docker compose' indisponible (Docker Compose v2 requis).$(RESET)\n"; \
	  exit 1; \
	}

check-env:
	@test -f .env || { \
	  printf "$(RED)X Fichier .env manquant.$(RESET)\n"; \
	  printf "   1. cp .env.example .env\n"; \
	  printf "   2. Éditer .env avec les vraies valeurs (SECRET_KEY, SQLCIPHER_KEY, ...)\n"; \
	  exit 1; \
	}

check-openssl:
	@command -v openssl >/dev/null 2>&1 || { \
	  printf "$(RED)X openssl introuvable — requis par 'make first-run' pour générer SECRET_KEY / SQLCIPHER_KEY.$(RESET)\n"; \
	  printf "   Installez-le (Debian/Ubuntu : apt-get install -y openssl) puis relancez.\n"; \
	  exit 1; \
	}

check-curl:
	@command -v curl >/dev/null 2>&1 || { \
	  printf "$(RED)X curl introuvable sur l'hôte — requis pour vérifier la santé de l'app (_wait-healthy).$(RESET)\n"; \
	  printf "   Installez-le (Debian/Ubuntu : apt-get install -y curl) puis relancez.\n"; \
	  exit 1; \
	}

# Validation anti-injection : autorisé = a-z A-Z 0-9 espace . _ / -
check-file:
	@if [ -z "$(FILE)" ]; then \
	  printf "$(RED)X Variable FILE non définie. Usage : make restore FILE=./backups/komptia-X.tar.gz$(RESET)\n"; \
	  exit 1; \
	fi
	@printf '%s' "$(FILE)" | grep -Eq '^[a-zA-Z0-9._/ -]+$$' || { \
	  printf "$(RED)X FILE contient des caractères interdits$(RESET)\n"; \
	  exit 1; \
	}

# --- Cycle de vie production ----------------------------------------

build: check-compose ## [PROD] Construit l'image Docker
	$(COMPOSE) build

rebuild: check-compose ## [PROD] Construit l'image SANS cache
	$(COMPOSE) build --no-cache

up: check-compose check-env ## [PROD] Démarre le container Docker
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory _print-access-url MSG="App démarrée sur "

down: check-compose ## [PROD] Arrête le container (données préservées)
	$(COMPOSE) down

restart: down up ## [PROD] Redémarre le container

update: check-compose check-env check-openssl ## [PROD] Met à jour vers le code déjà récupéré (rebuild + restart ; migrations AUTO au boot ; données préservées)
	@if sh scripts/keycheck.sh active 2>/dev/null; then \
	  STORED=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'cat /v/.keycheck 2>/dev/null' 2>/dev/null || true); \
	  if [ -n "$$STORED" ]; then \
	    sh scripts/keycheck.sh verify "$$STORED"; KCV=$$?; \
	    if [ "$$KCV" = 1 ]; then \
	      printf "$(RED)X La SQLCIPHER_KEY de .env ne correspond PAS à celle qui a chiffré le volume.$(RESET)\n"; \
	      printf "   Un force-recreate rendrait la BDD DÉFINITIVEMENT illisible (fail-closed au boot).\n"; \
	      printf "   -> Restaurez le .env d'origine (bonne SQLCIPHER_KEY) avant 'make update'.\n"; \
	      exit 1; \
	    elif [ "$$KCV" != 0 ]; then \
	      printf "$(RED)X Vérification de clé IMPOSSIBLE (openssl ?) — update REFUSÉ par sécurité. Vérifiez la clé à la main.$(RESET)\n"; \
	      exit 1; \
	    fi; \
	    printf "$(GREEN)+ Empreinte de clé OK — la clé .env ouvre bien le volume.$(RESET)\n"; \
	  else \
	    printf "$(YELLOW)! Pas d'empreinte de clé dans le volume (install antérieure) — 'make keycheck-refresh' (app saine) pour l'activer. Vérifiez que .env a la bonne SQLCIPHER_KEY.$(RESET)\n"; \
	  fi; \
	fi
	@printf "$(YELLOW)! 'make update' recrée le conteneur (force-recreate). Conseillé : 'make backup' avant une MAJ majeure (rollback = make restore FILE=...).$(RESET)\n"
	@printf "$(YELLOW)-> Mise à jour : reconstruction de l'image sans cache (nouvelles deps)...$(RESET)\n"
	$(COMPOSE) build --no-cache
	@printf "$(GREEN)-> Redémarrage sur la nouvelle image — les migrations BDD s'appliquent AU BOOT (init_database → _run_migrations), aucune étape manuelle...$(RESET)\n"
	$(COMPOSE) up -d --force-recreate
	@$(MAKE) --no-print-directory _wait-healthy
	@printf "$(GREEN)+ Mise à jour terminée : nouveau code actif, migrations appliquées, données du volume préservées.$(RESET)\n"

logs: check-compose ## [PROD] Logs en direct du container (Ctrl+C pour quitter)
	$(COMPOSE) logs -f --tail=200

status: check-compose ## [PROD] État du container + healthcheck
	@$(COMPOSE) ps
	@printf "\n"
	@if curl -fs $(HEALTH_URL) >/dev/null 2>&1; then \
	  printf "$(GREEN)+ Healthcheck OK$(RESET)\n"; \
	else \
	  printf "$(YELLOW)! Healthcheck KO (l'app peut être en cours de démarrage)$(RESET)\n"; \
	fi

container: check-compose ## [PROD] Ouvre un shell dans le container Docker
	@$(COMPOSE) exec $(SERVICE) bash 2>/dev/null || $(COMPOSE) exec $(SERVICE) sh

_wait-healthy: check-curl
	@printf "$(GREEN)-> Attente du démarrage de l'app...$(RESET)\n"
	@i=0; while [ $$i -lt $(HEALTH_TIMEOUT) ]; do \
	  if curl -fs $(HEALTH_URL) >/dev/null 2>&1; then \
	    printf "$(GREEN)+ App prête après %ss$(RESET)\n" "$$i"; exit 0; \
	  fi; \
	  sleep 1; i=$$((i+1)); \
	done; \
	CID=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null); \
	if [ -n "$$CID" ] && [ "$$(docker inspect -f '{{.State.Running}}' $$CID 2>/dev/null)" = "true" ]; then \
	  printf "$(YELLOW)! Le conteneur TOURNE mais /health n'a pas répondu en $(HEALTH_TIMEOUT)s.$(RESET)\n"; \
	  printf "   Probable boot long (grosse BDD / migration au 1er démarrage) — PAS un crash.\n"; \
	  printf "   Suivez 'make logs' ; patientez, ou relancez avec un délai plus large :\n"; \
	  printf "   make up HEALTH_TIMEOUT=300\n"; \
	else \
	  printf "$(RED)X App pas prête après $(HEALTH_TIMEOUT)s (conteneur arrêté/crash) — voir 'make logs'$(RESET)\n"; \
	fi; \
	exit 1

# Marqueur SSoT « installation complète » (data/.komptia_initialized dans le
# volume) — posé en FIN de first-run ET de reset. Le guard de first-run ne
# bloque QUE si ce marqueur existe ; absent = reprise. WORKDIR conteneur =
# /opt/komptia, le volume est monté sur data/ → racine du volume.
_mark-initialized:
	@$(COMPOSE) exec $(SERVICE) sh -c 'touch data/.komptia_initialized' \
	  || printf "$(YELLOW)! Marqueur d'init non écrit (non bloquant ; un prochain first-run tentera une reprise).$(RESET)\n"

# Pré-télécharge le modèle d'embeddings d'Iris (~440 Mo) DANS le conteneur en
# cours d'exécution → atterrit sous le volume (HF_HOME=data/hf_cache) et persiste.
# Appelé par first-run ET reset (les deux partent d'un volume neuf). NON BLOQUANT :
# si le serveur est hors-ligne au déploiement, le script sort en 0 (warning) et
# EmbeddingService re-tentera au 1er usage, en repli TF-IDF entre-temps. Iris
# n'est JAMAIS bloqué par les embeddings. (update ne l'appelle pas : le volume,
# donc le modèle, est préservé.)
_prefetch-models:
	@printf "$(GREEN)-> Pré-téléchargement du modèle d'embeddings Iris dans le volume (~440 Mo, non bloquant)...$(RESET)\n"
	@$(COMPOSE) exec $(SERVICE) python -m scripts.prefetch_models \
	  || printf "$(YELLOW)! Pré-téléchargement non abouti (non bloquant). Iris démarrera en repli TF-IDF ; relancez 'make prefetch-models' une fois le réseau dispo.$(RESET)\n"

prefetch-models: check-compose ## [PROD] (Re)télécharge le modèle d'embeddings Iris dans le volume — utile sur serveur isolé après rétablissement réseau
	@$(MAKE) --no-print-directory _prefetch-models

# --- LLM local (Ollama, sidecar optionnel) --------------------------
# Le sidecar `ollama` est gardé derrière le profil compose `llm-local` (ne
# démarre pas avec un `make up` normal). Ces cibles l'allument/éteignent et
# pré-téléchargent un modèle via l'API HTTP du sidecar. Ensuite : activer le
# LLM local dans /admin/ai-config (l'URL par défaut pointe déjà sur le sidecar).
llm-local-up: check-compose ## [PROD] Démarre le sidecar Ollama (LLM local CPU) — profil llm-local
	@printf "$(GREEN)-> Démarrage du sidecar Ollama (profil llm-local)...$(RESET)\n"
	$(COMPOSE) --profile llm-local up -d ollama
	@printf "$(GREEN)+ Sidecar Ollama démarré. Téléchargez un modèle : 'make llm-local-pull MODEL=llama3.2:3b' (ou via /admin/ai-config).$(RESET)\n"

llm-local-down: check-compose ## [PROD] Arrête le sidecar Ollama (les modèles restent dans le volume)
	@printf "$(YELLOW)-> Arrêt du sidecar Ollama...$(RESET)\n"
	$(COMPOSE) --profile llm-local stop ollama

llm-local-pull: check-compose ## [PROD] Pré-télécharge un modèle Ollama dans le sidecar — usage : make llm-local-pull MODEL=llama3.2:3b
	@if [ -z "$(MODEL)" ]; then \
	  printf "$(RED)X Variable MODEL non définie. Usage : make llm-local-pull MODEL=llama3.2:3b$(RESET)\n"; \
	  exit 1; \
	fi
	@printf "$(GREEN)-> Téléchargement du modèle '%s' dans le sidecar Ollama (peut être long)...$(RESET)\n" "$(MODEL)"
	$(COMPOSE) --profile llm-local exec ollama ollama pull "$(MODEL)"
	@printf "$(GREEN)+ Modèle '%s' prêt.$(RESET)\n" "$(MODEL)"

# Active le LLM local DE FAÇON PERSISTANTE : pose COMPOSE_PROFILES=llm-local dans
# .env (Compose v2 le lit → `make up`/`make update` démarrent le sidecar tout seuls,
# sans `--profile`), démarre la stack, puis pré-télécharge un modèle (non bloquant).
# Idempotent : ne double pas la ligne si déjà présente. Ensuite : activer l'USAGE
# dans /admin/ai-config (toggle + choix du modèle).
llm-local-enable: check-compose ## [PROD] Active le LLM local en 1 commande (persistant) : sidecar + modèle par défaut
	@if [ ! -f .env ]; then \
	  printf "$(RED)X .env absent — lancez 'make first-run' d'abord.$(RESET)\n"; exit 1; \
	fi
	@if grep -qE '^[[:space:]]*COMPOSE_PROFILES[[:space:]]*=([^#]*[,[:space:]])?llm-local([,[:space:]#]|$$)' .env; then \
	  printf "$(GREEN)+ COMPOSE_PROFILES=llm-local déjà actif dans .env.$(RESET)\n"; \
	elif grep -qE '^[[:space:]]*COMPOSE_PROFILES[[:space:]]*=' .env; then \
	  sed -i.bak -E 's|^([[:space:]]*COMPOSE_PROFILES[[:space:]]*=[^#[:space:]]*)|\1,llm-local|; s|^([[:space:]]*COMPOSE_PROFILES[[:space:]]*=),|\1|' .env && rm -f .env.bak; \
	  printf "$(GREEN)+ 'llm-local' ajouté à COMPOSE_PROFILES dans .env (valeur unquoted comma-separated attendue).$(RESET)\n"; \
	elif grep -qE '^[[:space:]]*#[[:space:]]*COMPOSE_PROFILES=llm-local' .env; then \
	  sed -i.bak -E 's|^[[:space:]]*#[[:space:]]*(COMPOSE_PROFILES=llm-local)|\1|' .env && rm -f .env.bak; \
	  printf "$(GREEN)+ COMPOSE_PROFILES=llm-local décommenté dans .env.$(RESET)\n"; \
	else \
	  printf 'COMPOSE_PROFILES=llm-local\n' >> .env; \
	  printf "$(GREEN)+ COMPOSE_PROFILES=llm-local ajouté à .env.$(RESET)\n"; \
	fi
	@printf "$(GREEN)-> Démarrage de la stack avec le sidecar Ollama...$(RESET)\n"
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory _prefetch-llm-local
	@printf "$(GREEN)+ LLM local activé (persistant). Dernière étape : /admin/ai-config -> activer + choisir le modèle.$(RESET)\n"

# Désactive le LLM local persistant : commente la ligne COMPOSE_PROFILES qui
# contient 'llm-local' et arrête le sidecar (les modèles restent dans le volume).
# Un seul profil existe dans ce projet (llm-local) → commenter la ligne entière est
# sûr et portable (BSD/GNU sed). L'ancre `^[[:space:]]*COMPOSE_PROFILES` ne matche
# pas une ligne déjà commencée par '#' → idempotent. L'app continue de tourner (fail-soft).
llm-local-disable: check-compose ## [PROD] Désactive le LLM local persistant + arrête le sidecar (modèles conservés)
	@if [ -f .env ] && grep -qE '^[[:space:]]*COMPOSE_PROFILES[[:space:]]*=.*llm-local' .env; then \
	  sed -i.bak -E 's|^([[:space:]]*COMPOSE_PROFILES[[:space:]]*=.*llm-local.*)|# \1|' .env && rm -f .env.bak; \
	  printf "$(GREEN)+ COMPOSE_PROFILES (llm-local) commenté dans .env.$(RESET)\n"; \
	else \
	  printf "$(YELLOW)! Aucune ligne COMPOSE_PROFILES active avec llm-local dans .env (rien à modifier).$(RESET)\n"; \
	fi
	@printf "$(YELLOW)-> Arrêt du sidecar Ollama (modèles conservés dans le volume)...$(RESET)\n"
	-$(COMPOSE) --profile llm-local stop ollama
	@printf "$(GREEN)+ LLM local désactivé. (Au prochain 'make up'/'make update' le sidecar ne redémarrera pas.)$(RESET)\n"

# Pré-télécharge le modèle Ollama par défaut DANS le sidecar — non bloquant et
# CONDITIONNEL : no-op silencieux si le sidecar n'est pas EN COURS (profil off, ou
# pas encore démarré). Détection par état RÉEL : `ps -q` ne renvoie un id que pour un
# conteneur qui TOURNE. On passe `--profile llm-local` pour que compose résolve le
# service quel que soit le mode d'activation (COMPOSE_PROFILES dans .env OU flag CLI
# transitoire). Attend la readiness du daemon (start_period healthcheck) avec un retry
# court avant le pull. Appelé par first-run/reset (no-op si profil off) et llm-local-enable.
_prefetch-llm-local:
	@CID=$$($(COMPOSE) --profile llm-local ps -q ollama 2>/dev/null); \
	if [ -z "$$CID" ]; then \
	  printf "$(YELLOW)! Sidecar Ollama inactif (profil llm-local désactivé) — pré-téléchargement du modèle ignoré.$(RESET)\n"; \
	  exit 0; \
	fi; \
	printf "$(GREEN)-> Sidecar Ollama actif : attente readiness + pull '%s' (non bloquant)...$(RESET)\n" "$(OLLAMA_DEFAULT_MODEL)"; \
	i=0; while [ $$i -lt 30 ]; do \
	  if $(COMPOSE) --profile llm-local exec -T ollama ollama list >/dev/null 2>&1; then break; fi; \
	  sleep 2; i=$$((i+1)); \
	done; \
	$(COMPOSE) --profile llm-local exec -T ollama ollama pull "$(OLLAMA_DEFAULT_MODEL)" \
	  && printf "$(GREEN)+ Modèle '%s' prêt dans le sidecar.$(RESET)\n" "$(OLLAMA_DEFAULT_MODEL)" \
	  || printf "$(YELLOW)! Pull de '%s' non abouti (non bloquant). Réessayez via /admin/ai-config (bouton Télécharger) ou 'make llm-local-pull MODEL=%s'.$(RESET)\n" "$(OLLAMA_DEFAULT_MODEL)" "$(OLLAMA_DEFAULT_MODEL)"

# Affiche l'URL d'ACCÈS réelle (single source of truth). En déploiement derrière
# reverse-proxy, l'app n'est PAS accessible sur 127.0.0.1:8888 (port loopback
# interne du conteneur) mais via le SERVER_NAME configuré par 'make deploy-config'
# (persisté en KOMPTIA_ALLOWED_ORIGINS=scheme://host dans .env). En dev local sans
# config de déploiement, on retombe sur le loopback. Appelé via MSG="préfixe ".
_print-access-url:
	@url=$$(grep -E '^KOMPTIA_ALLOWED_ORIGINS=' .env 2>/dev/null | tail -1 \
	  | sed -E 's/^[^=]*=//' | tr -d "\"' \r" | cut -d, -f1); \
	case "$$url" in http://*|https://*) ;; *) url="" ;; esac; \
	[ -n "$$url" ] || url="http://127.0.0.1:8888"; \
	printf "\n$(GREEN)+ %s%s$(RESET)\n" "$(MSG)" "$$url"; \
	if [ "$$url" != "http://127.0.0.1:8888" ]; then \
	  printf "$(YELLOW)  (port interne du conteneur : http://127.0.0.1:8888 — l'accès se fait via le reverse-proxy)$(RESET)\n"; \
	fi

# Purge KOMPTIA_ADMIN_PASSWORD du .env + de l'env live du conteneur (anti-fuite
# via docker inspect). Idempotent : no-op si la variable n'est pas présente.
# Partagé par first-run ET reset (sinon reset garderait un mot de passe de test).
_scrub-admin-password:
	@if [ -f .env ] && grep -qE '^KOMPTIA_ADMIN_PASSWORD=.+' .env; then \
	  printf "$(GREEN)-> Purge de KOMPTIA_ADMIN_PASSWORD (.env + env conteneur)...$(RESET)\n"; \
	  sh scripts/scrub_dotenv_value.sh .env KOMPTIA_ADMIN_PASSWORD; \
	  { $(COMPOSE) up -d --force-recreate && $(MAKE) --no-print-directory _wait-healthy; } \
	    && printf "$(GREEN)+ KOMPTIA_ADMIN_PASSWORD purgé.$(RESET)\n" \
	    || printf "$(YELLOW)! Purge: recreate/healthcheck non abouti (NON bloquant — la valeur est déjà retirée du .env ; relancez 'make up' si besoin).$(RESET)\n"; \
	fi

# Écrit l'empreinte (HMAC NON-secret) de SQLCIPHER_KEY dans le volume
# (data/.keycheck) → base des gardes « cette clé ouvre-t-elle ce volume/backup ? »
# de make update / make restore. No-op en mode clair (pas de clé).
_write-keycheck:
	@if sh scripts/keycheck.sh active 2>/dev/null; then \
	  FP=$$(sh scripts/keycheck.sh compute 2>/dev/null); \
	  if [ -z "$$FP" ]; then \
	    printf "$(RED)! Empreinte de clé NON calculée (openssl absent/muet) — gardes restore/update DÉSACTIVÉES pour cette install.$(RESET)\n"; \
	    printf "$(RED)  Installez openssl puis 'make keycheck-refresh' (app saine requise).$(RESET)\n"; \
	  else \
	    docker run --rm -v $(VOLUME):/v $(ALPINE_IMG) sh -c "printf '%s' '$$FP' > /v/.keycheck" 2>/dev/null || true; \
	    BACK=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) cat /v/.keycheck 2>/dev/null || true); \
	    if [ "$$BACK" = "$$FP" ]; then \
	      printf "$(GREEN)+ Empreinte de clé SQLCipher enregistrée (anti-mismatch restore/update).$(RESET)\n"; \
	    else \
	      printf "$(RED)! Écriture de l'empreinte ÉCHOUÉE (read-back KO) — gardes restore/update non garanties. Réessayez 'make keycheck-refresh'.$(RESET)\n"; \
	    fi; \
	  fi; \
	fi

keycheck-refresh: check-compose check-curl check-openssl ## [PROD] Ré-enregistre l'empreinte de la clé SQLCipher courante (après rotation de clé légitime). Exige l'app SAINE.
	@if ! sh scripts/keycheck.sh active 2>/dev/null; then \
	  printf "$(YELLOW)! Mode clair (pas de SQLCIPHER_KEY) — rien à enregistrer.$(RESET)\n"; \
	elif curl -fs $(HEALTH_URL) >/dev/null 2>&1; then \
	  printf "$(GREEN)-> App saine : la clé courante ouvre bien la BDD → ré-enregistrement de l'empreinte...$(RESET)\n"; \
	  $(MAKE) --no-print-directory _write-keycheck; \
	else \
	  printf "$(RED)X App pas saine — impossible de prouver que la clé courante ouvre la BDD.$(RESET)\n"; \
	  printf "   Refresh REFUSÉ (on n'enregistre jamais une empreinte pour une clé non prouvée — sinon update/restore valideraient une mauvaise clé).\n"; \
	  printf "   Démarrez l'app avec la bonne clé ('make up') puis réessayez.\n"; \
	  exit 1; \
	fi

# --- Première installation production -------------------------------

first-run: check-compose check-openssl ## [PROD] Première installation : auto-config (.env, clés) + build + démarre + bootstrap admin
	@if [ ! -f .env ]; then \
	  printf "$(YELLOW)-> .env absent, création depuis .env.example...$(RESET)\n"; \
	  cp .env.example .env && chmod 600 .env; \
	  printf "$(GREEN)+ .env créé$(RESET)\n"; \
	fi
	@if grep -q "^SECRET_KEY=CHANGE_ME" .env 2>/dev/null; then \
	  KEY=$$(openssl rand -hex 32); \
	  if [ -z "$$KEY" ]; then printf "$(RED)X Génération SECRET_KEY échouée (openssl muet) — clé VIDE refusée (sinon boot non chiffré silencieux).$(RESET)\n"; exit 1; fi; \
	  sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$$KEY|" .env && rm -f .env.bak; \
	  printf "$(GREEN)+ SECRET_KEY générée automatiquement$(RESET)\n"; \
	fi
	@if grep -q "^SQLCIPHER_KEY=CHANGE_ME" .env 2>/dev/null; then \
	  KEY=$$(openssl rand -hex 32); \
	  if [ -z "$$KEY" ]; then printf "$(RED)X Génération SQLCIPHER_KEY échouée (openssl muet) — clé VIDE refusée (sinon BDD non chiffrée silencieuse).$(RESET)\n"; exit 1; fi; \
	  sed -i.bak "s|^SQLCIPHER_KEY=.*|SQLCIPHER_KEY=$$KEY|" .env && rm -f .env.bak; \
	  printf "$(GREEN)+ SQLCIPHER_KEY générée automatiquement$(RESET)\n"; \
	fi
	@if docker volume inspect $(VOLUME) >/dev/null 2>&1; then \
	  HAS_DATA=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'ls -A /v | head -1' 2>/dev/null); \
	  INITIALIZED=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'test -f /v/.komptia_initialized && echo yes' 2>/dev/null); \
	  if [ -n "$$HAS_DATA" ] && [ -n "$$INITIALIZED" ]; then \
	    printf "$(RED)X Le volume $(VOLUME) contient déjà une installation COMPLÈTE.$(RESET)\n"; \
	    printf "   - Pour redémarrer normalement : 'make up'\n"; \
	    printf "   - Pour repartir de zéro : 'make reset' (avec backup auto)\n"; \
	    exit 1; \
	  elif [ -n "$$HAS_DATA" ]; then \
	    MAGIC=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'head -c 15 /v/komptia.db 2>/dev/null' 2>/dev/null || true); \
	    if sh scripts/keycheck.sh active 2>/dev/null && [ "$$MAGIC" = "SQLite format 3" ]; then \
	      printf "$(RED)X Volume existant avec une BDD EN CLAIR + SQLCIPHER_KEY définie (install pré-chiffrement).$(RESET)\n"; \
	      printf "   La reprise crasherait (fail-closed : une base claire ne s'ouvre pas avec une clé).\n"; \
	      printf "   -> Volume neuf obligatoire : 'docker compose down -v' puis 'make first-run'.\n"; \
	      printf "      (la BDD claire existante sera perdue — sauvegardez-la avant si nécessaire)\n"; \
	      exit 1; \
	    fi; \
	    printf "$(YELLOW)! Volume présent mais installation INCOMPLÈTE (marqueur absent).$(RESET)\n"; \
	    printf "$(YELLOW)  -> REPRISE du first-run (db_init + création admin sont idempotents).$(RESET)\n"; \
	  fi; \
	fi
	@printf "$(GREEN)-> Construction de l'image et démarrage...$(RESET)\n"
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory _wait-healthy
ifndef SKIP_PREFLIGHT
	@printf "$(GREEN)-> Préflight : validation de la config de déploiement...$(RESET)\n"
	@$(COMPOSE) exec $(SERVICE) python -m scripts.preflight || { \
	  printf "$(RED)X Préflight : erreurs de config détectées (voir ci-dessus).$(RESET)\n"; \
	  printf "   Corrigez .env / config.yaml (ex: 'make deploy-config SERVER_NAME=...'), puis relancez 'make first-run'.\n"; \
	  printf "   Pour ignorer (dev/test local) : 'make first-run SKIP_PREFLIGHT=1'.\n"; \
	  exit 1; \
	}
endif
	@printf "$(GREEN)-> Initialisation de la base de données...$(RESET)\n"
	$(COMPOSE) exec $(SERVICE) python -m scripts.db_init
	@printf "$(GREEN)-> Création du compte administrateur...$(RESET)\n"
	@printf "$(YELLOW)   (interactif — ou définir KOMPTIA_ADMIN_USERNAME/EMAIL/PASSWORD dans .env)$(RESET)\n"
	$(COMPOSE) exec $(SERVICE) python -m scripts.seed_admin
	@$(MAKE) --no-print-directory _scrub-admin-password
	@$(MAKE) --no-print-directory _prefetch-models
	@$(MAKE) --no-print-directory _prefetch-llm-local
	@printf "$(GREEN)-> Marque l'installation complète + empreinte de clé SQLCipher...$(RESET)\n"
	@$(MAKE) --no-print-directory _mark-initialized
	@$(MAKE) --no-print-directory _write-keycheck
	@$(MAKE) --no-print-directory _print-access-url MSG="Komptia est prêt sur "

# --- Configuration déploiement (reverse-proxy) ----------------------

# Validation : SERVER_NAME requis (IP LAN ou domaine public d'accès client).
check-server-name:
	@if [ -z "$(SERVER_NAME)" ]; then \
	  printf "$(RED)X Variable SERVER_NAME non définie.$(RESET)\n"; \
	  printf "   Usage : make deploy-config SERVER_NAME=192.168.1.10  (ou =komptia.client.fr)\n"; \
	  exit 1; \
	fi

deploy-config: check-env check-server-name ## [PROD] Config reverse-proxy (ALLOWED_ORIGINS + trust_proxy [+ TZ=...]) depuis SERVER_NAME
	@printf "$(GREEN)-> Configuration déploiement (origines WebSocket + trust_proxy_headers) pour %s...$(RESET)\n" "$(SERVER_NAME)"
	$(PYTHON) -m scripts.setup_deploy_env --server-name "$(SERVER_NAME)" $(if $(strip $(TZ)),--timezone "$(TZ)")
	@printf "$(GREEN)+ Config posée dans .env / config.yaml.$(RESET)\n"
	@printf "$(YELLOW)  Reverse-proxy nginx hôte (cert + site, root/Linux) : 'make production-setup SERVER_NAME=...'.$(RESET)\n"

# Garde : le reverse-proxy nginx hôte (systemctl, root, chemins Debian) n'a de
# sens que sur le serveur Linux de prod — JAMAIS sur le Mac dev (pile en Docker).
check-linux:
	@if [ "$$(uname -s)" != "Linux" ]; then \
	  printf "$(RED)X 'make production-setup' nécessite Linux (nginx hôte : systemctl, root, /etc/nginx).$(RESET)\n"; \
	  printf "   Sur Mac/dev : la pile tourne en Docker ('make up') ; le reverse-proxy hôte est pour le serveur de prod.\n"; \
	  exit 1; \
	fi

production-setup: check-server-name check-linux ## [PROD/Linux] Setup serveur : reverse-proxy (.env/config.yaml [+TZ=...]) + nginx hôte (cert+site) + timer renouvellement cert. À lancer en root.
	@printf "$(GREEN)-> [1/3] Config reverse-proxy (.env / config.yaml)...$(RESET)\n"
	@$(MAKE) --no-print-directory deploy-config SERVER_NAME="$(SERVER_NAME)" TZ="$(TZ)"
	@printf "$(GREEN)-> [2/3] Reverse-proxy nginx hôte (cert auto-signé + zones limit_req + site + reload)...$(RESET)\n"
	$(PYTHON) -m scripts.setup_host_nginx --server-name "$(SERVER_NAME)" $(if $(strip $(ALT)),--alt "$(ALT)")
	@printf "$(GREEN)-> [3/3] Timer systemd de renouvellement automatique du cert (vérif trimestrielle)...$(RESET)\n"
	$(PYTHON) -m scripts.install_cert_timer
	@printf "$(GREEN)+ Setup production OK pour %s. Ensuite : 'make first-run' (build + db_init + admin).$(RESET)\n" "$(SERVER_NAME)"

cert-renew-timer: check-linux ## [PROD/Linux] (Ré)installe le timer cert (root). Idempotent — pour un serveur DÉJÀ déployé (sinon production-setup le pose).
	@printf "$(GREEN)-> Installation du timer systemd : vérification trimestrielle, régénération à l'approche de l'expiration...$(RESET)\n"
	$(PYTHON) -m scripts.install_cert_timer
	@printf "$(GREEN)+ Timer installé. État : systemctl list-timers komptia-cert-renew.timer$(RESET)\n"
	@printf "$(YELLOW)  Surveillance des échecs : journalctl -u komptia-cert-renew.service (oneshot trimestriel).$(RESET)\n"

# --- Backup / Restore / Reset ---------------------------------------

backup: check-compose ## [PROD] Sauvegarde toutes les données dans ./backups/
	@set -e; \
	if ! docker volume inspect $(VOLUME) >/dev/null 2>&1; then \
	  printf "$(RED)X Volume $(VOLUME) inexistant — rien à sauvegarder.$(RESET)\n"; \
	  printf "   Lancez 'make first-run' d'abord.\n"; \
	  exit 1; \
	fi; \
	HAS_DATA=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'ls -A /v | head -1' 2>/dev/null); \
	if [ -z "$$HAS_DATA" ]; then \
	  printf "$(RED)X Volume $(VOLUME) vide — rien à sauvegarder.$(RESET)\n"; \
	  exit 1; \
	fi; \
	mkdir -p "$(BACKUP_DIR)"; \
	chmod 700 "$(BACKUP_DIR)"; \
	OUTFILE="$(BACKUP_DIR)/komptia-$(TIMESTAMP).tar.gz"; \
	TMP=$$(mktemp -d "./.komptia-tmp.XXXXXX"); \
	TMP=$$(cd "$$TMP" && pwd); \
	chmod 700 "$$TMP"; \
	WAS_RUNNING=0; \
	if [ -z "$(HOT)" ]; then \
	  CID=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null); \
	  if [ -n "$$CID" ] && [ "$$(docker inspect -f '{{.State.Running}}' $$CID 2>/dev/null)" = "true" ]; then \
	    WAS_RUNNING=1; \
	    printf "$(YELLOW)-> Arrêt du container (cohérence SQLite)...$(RESET)\n"; \
	    $(COMPOSE) stop; \
	  fi; \
	else \
	  if sh scripts/keycheck.sh active 2>/dev/null; then \
	    printf "$(RED)X HOT=1 incompatible avec le chiffrement SQLCipher.$(RESET)\n"; \
	    printf "   Un tar à chaud des fichiers WAL chiffrés produirait un backup ILLISIBLE (pas seulement les derniers commits perdus — base entière inouvrable).\n"; \
	    printf "   -> Utilisez le backup à froid : 'make backup' (sans HOT=1) — arrêt bref du conteneur, snapshot cohérent.\n"; \
	    rm -rf "$$TMP"; \
	    exit 1; \
	  fi; \
	  printf "$(YELLOW)! HOT=1 : backup à chaud (base EN CLAIR) — cohérence SQLite non garantie sur écritures concurrentes.$(RESET)\n"; \
	fi; \
	printf "$(GREEN)-> Snapshot du volume $(VOLUME)...$(RESET)\n"; \
	docker run --rm -v "$(VOLUME):/source:ro" -v "$$TMP:/dest" $(ALPINE_IMG) \
	  sh -c "cd /source && tar czf /dest/data.tar.gz ."; \
	test -f "$$TMP/data.tar.gz" || { \
	  printf "$(RED)X Échec snapshot : data.tar.gz absent (bind-mount $$TMP non accessible depuis Docker ?)$(RESET)\n"; \
	  printf "   Sur macOS avec Colima : vérifier que /tmp est monté.\n"; \
	  rm -rf "$$TMP"; \
	  if [ "$$WAS_RUNNING" = "1" ]; then $(COMPOSE) start; fi; \
	  exit 1; \
	}; \
	if [ -n "$(INCLUDE_ENV)" ] && [ -f .env ]; then cp .env "$$TMP/.env" && chmod 600 "$$TMP/.env"; fi; \
	if [ -f config.yaml ]; then cp config.yaml "$$TMP/config.yaml"; fi; \
	DATA_SIZE=$$(du -sh "$$TMP/data.tar.gz" | cut -f1); \
	BDATE=$$(date +"%Y-%m-%dT%H:%M:%S%z"); \
	printf '{\n  "backup_date": "%s",\n  "data_size": "%s",\n  "format_version": "1"\n}\n' \
	  "$$BDATE" "$$DATA_SIZE" > "$$TMP/metadata.json"; \
	tar czf "$$OUTFILE" -C "$$TMP" .; \
	chmod 600 "$$OUTFILE"; \
	rm -rf "$$TMP"; \
	if [ "$$WAS_RUNNING" = "1" ]; then \
	  printf "$(GREEN)-> Redémarrage du container...$(RESET)\n"; \
	  $(COMPOSE) start; \
	fi; \
	SIZE=$$(du -h "$$OUTFILE" | cut -f1); \
	printf "$(GREEN)+ Backup créé : %s (%s)$(RESET)\n" "$$OUTFILE" "$$SIZE"; \
	if [ -n "$(INCLUDE_ENV)" ]; then \
	  printf "$(YELLOW)! Le backup CONTIENT .env (clé SQLCIPHER + données dans la même archive) — protégez-le comme la clé elle-même.$(RESET)\n"; \
	else \
	  printf "$(GREEN)+ Backup SANS .env (séparation clé/données) : conservez SQLCIPHER_KEY séparément pour pouvoir restaurer. Archive autonome : 'make backup INCLUDE_ENV=1' (déconseillé).$(RESET)\n"; \
	fi

restore: check-compose check-file check-openssl ## [PROD] Restaure depuis un backup : make restore FILE=./backups/komptia-X.tar.gz
	@set -e; \
	if [ ! -f "$(FILE)" ]; then \
	  printf "$(RED)X Fichier introuvable : %s$(RESET)\n" "$(FILE)"; \
	  exit 1; \
	fi; \
	printf "$(YELLOW)-> Vérification de l'intégrité de l'archive...$(RESET)\n"; \
	tar tzf "$(FILE)" >/dev/null || { printf "$(RED)X Archive corrompue.$(RESET)\n"; exit 1; }; \
	tar tzf "$(FILE)" | grep -Eq '(^|/)data\.tar\.gz$$' || { \
	  printf "$(RED)X Archive non-Komptia (data.tar.gz manquant)$(RESET)\n"; exit 1; \
	}; \
	META=$$(tar xzOf "$(FILE)" ./metadata.json 2>/dev/null || echo ""); \
	if [ -n "$$META" ]; then \
	  printf "$(BLUE)Métadonnées du backup :$(RESET)\n"; \
	  echo "$$META" | sed 's/^/  /'; \
	fi; \
	FMT=$$(printf '%s' "$$META" | grep -oE '"format_version"[^0-9]*[0-9]+' | grep -oE '[0-9]+$$' | head -1); \
	if [ -n "$$FMT" ] && [ "$$FMT" -gt 1 ] 2>/dev/null; then \
	  printf "$(RED)X Format de backup v%s non supporté par cette version de Komptia (max v1).$(RESET)\n" "$$FMT"; \
	  printf "   Mettez à jour Komptia avant de restaurer ce backup.\n"; \
	  exit 1; \
	fi; \
	printf "\n$(YELLOW)! Cette opération va REMPLACER toutes les données par le contenu de %s$(RESET)\n" "$(FILE)"; \
	printf "Tape 'RESTORE' pour confirmer : "; \
	read CONFIRM; \
	if [ "$$CONFIRM" != "RESTORE" ]; then printf "$(YELLOW)Annulé.$(RESET)\n"; exit 1; fi; \
	TMP=$$(mktemp -d "./.komptia-tmp.XXXXXX"); \
	TMP=$$(cd "$$TMP" && pwd); \
	chmod 700 "$$TMP"; \
	tar xzf "$(FILE)" --no-same-owner --no-same-permissions -C "$$TMP"; \
	if [ ! -f "$$TMP/data.tar.gz" ]; then \
	  printf "$(RED)X Archive invalide (data.tar.gz manquant après extraction)$(RESET)\n"; \
	  rm -rf "$$TMP"; exit 1; \
	fi; \
	printf "$(GREEN)-> Vérification du contenu du backup AVANT reset destructif...$(RESET)\n"; \
	BK_FILES=$$(tar tzf "$$TMP/data.tar.gz" 2>/dev/null | grep -cvE '/$$' || true); \
	if [ "$${BK_FILES:-0}" -lt 1 ]; then \
	  printf "$(RED)X Backup vide ou illisible (0 fichier dans data.tar.gz) — restore ANNULÉ, volume live PRÉSERVÉ.$(RESET)\n"; \
	  rm -rf "$$TMP"; exit 1; \
	fi; \
	printf "$(GREEN)+ Backup vérifié (%s fichier(s)) — reset destructif autorisé.$(RESET)\n" "$$BK_FILES"; \
	if sh scripts/keycheck.sh active 2>/dev/null && [ ! -f "$$TMP/.env" ]; then \
	  BK_KEYCHECK=$$(tar xzOf "$$TMP/data.tar.gz" ./.keycheck 2>/dev/null || tar xzOf "$$TMP/data.tar.gz" .keycheck 2>/dev/null || true); \
	  if [ -n "$$BK_KEYCHECK" ]; then \
	    sh scripts/keycheck.sh verify "$$BK_KEYCHECK"; KCV=$$?; \
	    if [ "$$KCV" = 1 ]; then \
	      printf "$(RED)X La SQLCIPHER_KEY de votre .env n'ouvre PAS ce backup (empreinte différente).$(RESET)\n"; \
	      printf "   Restore ANNULÉ, volume live PRÉSERVÉ. Restaurez le .env d'origine (bonne clé) puis réessayez.\n"; \
	      rm -rf "$$TMP"; exit 1; \
	    elif [ "$$KCV" != 0 ]; then \
	      printf "$(RED)X Vérification de clé IMPOSSIBLE (openssl ?) — restore REFUSÉ par sécurité, volume live PRÉSERVÉ.$(RESET)\n"; \
	      rm -rf "$$TMP"; exit 1; \
	    fi; \
	    printf "$(GREEN)+ Empreinte de clé OK — votre .env ouvre bien ce backup.$(RESET)\n"; \
	  else \
	    printf "$(YELLOW)! Backup sans empreinte de clé (antérieur à ce garde) — vérification impossible.$(RESET)\n"; \
	    printf "$(YELLOW)  Assurez-vous que .env contient la SQLCIPHER_KEY de CE backup, sinon l'app crashera au boot.$(RESET)\n"; \
	  fi; \
	fi; \
	printf "$(GREEN)-> Sauvegarde de l'état actuel avant restore...$(RESET)\n"; \
	if [ -f .env ]; then cp .env ".env.before-restore-$(TIMESTAMP)" && chmod 600 ".env.before-restore-$(TIMESTAMP)"; fi; \
	if [ -f config.yaml ]; then cp config.yaml "config.yaml.before-restore-$(TIMESTAMP)"; fi; \
	printf "$(GREEN)-> Arrêt du container...$(RESET)\n"; \
	$(COMPOSE) down; \
	printf "$(GREEN)-> Reset du volume $(VOLUME)...$(RESET)\n"; \
	if docker volume inspect $(VOLUME) >/dev/null 2>&1; then \
	  ERR=$$(docker volume rm $(VOLUME) 2>&1) || { \
	    printf "$(RED)X Impossible de supprimer le volume :$(RESET)\n  %s\n" "$$ERR"; \
	    rm -rf "$$TMP"; exit 1; \
	  }; \
	fi; \
	docker volume create $(VOLUME) >/dev/null; \
	printf "$(GREEN)-> Restauration des données dans le volume...$(RESET)\n"; \
	docker run --rm -v "$(VOLUME):/dest" -v "$$TMP:/src:ro" $(ALPINE_IMG) \
	  sh -c "cd /dest && tar xzf /src/data.tar.gz --no-same-owner --no-same-permissions"; \
	if [ -f "$$TMP/.env" ]; then \
	  cp "$$TMP/.env" .env && chmod 600 .env; \
	  printf "$(GREEN)+ .env restauré (ancien : .env.before-restore-$(TIMESTAMP))$(RESET)\n"; \
	else \
	  printf "$(YELLOW)! .env absent du backup — l'ancien .env est conservé.$(RESET)\n"; \
	  printf "$(YELLOW)  Si la BDD ne s'ouvre pas, c'est que la SQLCIPHER_KEY ne correspond pas.$(RESET)\n"; \
	fi; \
	if [ -f "$$TMP/config.yaml" ]; then \
	  cp "$$TMP/config.yaml" config.yaml; \
	  printf "$(GREEN)+ config.yaml restauré$(RESET)\n"; \
	fi; \
	rm -rf "$$TMP"; \
	printf "$(GREEN)-> Démarrage du container...$(RESET)\n"; \
	$(COMPOSE) up -d; \
	$(MAKE) --no-print-directory _wait-healthy || { \
	  printf "$(RED)X L'app n'est pas devenue saine après restore.$(RESET)\n"; \
	  printf "   Cause probable : la SQLCIPHER_KEY de .env ne correspond pas à ce backup (voir 'make logs').\n"; \
	  printf "   L'ancien .env est sauvegardé : .env.before-restore-$(TIMESTAMP)\n"; \
	  exit 1; \
	}; \
	printf "$(GREEN)+ Restore terminé — app saine sur http://127.0.0.1:8888$(RESET)\n"

reset: check-compose check-env check-openssl ## [PROD] ! Efface TOUTES les données et re-bootstrap (backup auto, sauf NO_BACKUP=1)
	@printf "$(YELLOW)! Cette opération EFFACE toutes les données (BDD, rapports, logs, classeurs).$(RESET)\n"
	@printf "$(YELLOW)   .env et config.yaml sont préservés (PAS adapté pour mise en prod nouveau client — voir COMMANDES.md).$(RESET)\n"
	@printf "Tape 'RESET' pour confirmer : "
	@read CONFIRM; if [ "$$CONFIRM" != "RESET" ]; then printf "$(YELLOW)Annulé.$(RESET)\n"; exit 1; fi
ifndef NO_BACKUP
	@if docker volume inspect $(VOLUME) >/dev/null 2>&1 && \
	    [ -n "$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'ls -A /v | head -1' 2>/dev/null)" ]; then \
	  if sh scripts/keycheck.sh active 2>/dev/null; then \
	    KCS=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'cat /v/.keycheck 2>/dev/null' 2>/dev/null || true); \
	    if [ -n "$$KCS" ]; then sh scripts/keycheck.sh verify "$$KCS"; KCV=$$?; \
	      if [ "$$KCV" = 1 ]; then \
	        printf "$(RED)! ATTENTION : votre .env NE matche PAS le volume → le backup auto sera chiffré avec la clé du VOLUME (≠ .env). Ayez la clé du VOLUME, sinon ce backup sera IRRÉCUPÉRABLE.$(RESET)\n"; \
	      fi; \
	    fi; \
	    printf "$(YELLOW)! Le backup auto NE contient PAS la clé (séparation clé/données). Notez votre SQLCIPHER_KEY MAINTENANT, sinon ce backup sera illisible :$(RESET)\n"; \
	    printf "$(YELLOW)    grep ^SQLCIPHER_KEY= .env$(RESET)\n"; \
	  fi; \
	  printf "$(GREEN)-> Backup automatique avant reset...$(RESET)\n"; \
	  $(MAKE) --no-print-directory backup INCLUDE_ENV=; \
	else \
	  printf "$(YELLOW)! Pas de backup auto (volume vide).$(RESET)\n"; \
	fi
endif
	@set -e; \
	printf "$(GREEN)-> Arrêt du container...$(RESET)\n"; \
	$(COMPOSE) down; \
	printf "$(GREEN)-> Reset du volume $(VOLUME)...$(RESET)\n"; \
	if docker volume inspect $(VOLUME) >/dev/null 2>&1; then \
	  ERR=$$(docker volume rm $(VOLUME) 2>&1) || { \
	    printf "$(RED)X Impossible de supprimer le volume :$(RESET)\n  %s\n" "$$ERR"; \
	    printf "   Vérifier les containers attachés : docker ps -a --filter volume=$(VOLUME)\n"; \
	    exit 1; \
	  }; \
	fi; \
	docker volume create $(VOLUME) >/dev/null; \
	printf "$(GREEN)-> Démarrage du container...$(RESET)\n"; \
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory _wait-healthy
	@printf "$(GREEN)-> Initialisation BDD...$(RESET)\n"
	$(COMPOSE) exec $(SERVICE) python -m scripts.db_init
	@printf "$(GREEN)-> Création du compte administrateur...$(RESET)\n"
	$(COMPOSE) exec $(SERVICE) python -m scripts.seed_admin
	@$(MAKE) --no-print-directory _scrub-admin-password
	@$(MAKE) --no-print-directory _prefetch-models
	@$(MAKE) --no-print-directory _prefetch-llm-local
	@$(MAKE) --no-print-directory _mark-initialized
	@$(MAKE) --no-print-directory _write-keycheck
	@$(MAKE) --no-print-directory _print-access-url MSG="Reset terminé. Compta vierge prête sur "

vacuum: check-compose ## [PROD] Compacte la BDD locale (VACUUM in-place, OFFLINE) — rend l'espace après purges TTL
	@set -e; \
	if ! docker volume inspect $(VOLUME) >/dev/null 2>&1; then \
	  printf "$(RED)X Volume $(VOLUME) inexistant — rien à compacter.$(RESET)\n"; \
	  exit 1; \
	fi; \
	HAS_DATA=$$(docker run --rm -v $(VOLUME):/v:ro $(ALPINE_IMG) sh -c 'ls -A /v | head -1' 2>/dev/null); \
	if [ -z "$$HAS_DATA" ]; then \
	  printf "$(RED)X Volume $(VOLUME) vide — rien à compacter.$(RESET)\n"; \
	  exit 1; \
	fi; \
	WAS_RUNNING=0; \
	CID=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null); \
	if [ -n "$$CID" ] && [ "$$(docker inspect -f '{{.State.Running}}' $$CID 2>/dev/null)" = "true" ]; then \
	  WAS_RUNNING=1; \
	  printf "$(YELLOW)-> Arrêt du container (VACUUM exige un accès exclusif à SQLite)...$(RESET)\n"; \
	  $(COMPOSE) stop; \
	fi; \
	printf "$(GREEN)-> VACUUM en cours (peut être long sur une grosse BDD)...$(RESET)\n"; \
	VAC_RC=0; \
	$(COMPOSE) run --rm --no-deps $(SERVICE) python -m scripts.vacuum_db || VAC_RC=$$?; \
	if [ "$$WAS_RUNNING" = "1" ]; then \
	  printf "$(GREEN)-> Redémarrage du container...$(RESET)\n"; \
	  $(COMPOSE) start; \
	fi; \
	if [ "$$VAC_RC" != "0" ]; then \
	  printf "$(RED)X VACUUM échoué (code %s) — container redémarré, BDD intacte.$(RESET)\n" "$$VAC_RC"; \
	  exit $$VAC_RC; \
	fi; \
	printf "$(GREEN)+ VACUUM terminé.$(RESET)\n"

# =================================================
# Utilitaires
# =================================================

ollama-check: ## Vérifie que Ollama est disponible
	@curl -s http://localhost:11434/api/tags > /dev/null && echo "$(GREEN)✓ Ollama OK$(RESET)" || echo "$(YELLOW)⚠ Ollama non disponible$(RESET)"

ollama-pull: ## Télécharge le modèle Ollama (anonymiseur local) — binaire local (dev)
	ollama pull "$(OLLAMA_DEFAULT_MODEL)"

tree: ## Affiche l'arborescence du projet
	tree -I 'venv|__pycache__|.git|node_modules' -L 3

loc: ## Compte les lignes de code
	@find app tests -name "*.py" -exec wc -l {} + | tail -1 | awk '{print "Total lignes Python: " $$1}'

# =====================================================================
# MAINTENANCE — Génération et synchronisation des repos clients
# =====================================================================
# `generate-client-repo` : crée un repo client propre depuis appfazia
#                          (à lancer depuis appfazia)
# `sync-from-appfazia`   : met à jour un repo client existant
#                          (à lancer depuis le repo CLIENT, pas appfazia)
# =====================================================================

# Path source pour sync-from-appfazia (override possible)
APPFAZIA_PATH ?= ../appfazia

lock: check-docker ## [MAINT] Génère requirements.lock fidèle à la prod (build-deps du builder Dockerfile) DANS python:3.12-slim
	@printf "$(GREEN)-> Génération de requirements.lock (versions transitives figées, fidèle au builder Dockerfile)...$(RESET)\n"
	@printf "$(YELLOW)  (JAMAIS sur Mac directement : les wheels macOS produiraient un lock faux pour Linux.)$(RESET)\n"
	@docker run --rm -v "$(PWD):/w" -w /w python:3.12-slim sh -c 'set -e; \
	  apt-get update -qq >/dev/null; \
	  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
	    gcc g++ unixodbc-dev libffi-dev libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 >/dev/null; \
	  pip install -q --upgrade pip; \
	  pip install -q torch --index-url https://download.pytorch.org/whl/cpu; \
	  pip install -q -r requirements.txt; \
	  { echo "# requirements.lock — versions transitives figees (make lock : python:3.12-slim + build-deps du Dockerfile builder)."; \
	    echo "# Regenere depuis requirements.txt (dernier compatible) ; sert ensuite de base reproductible au build."; \
	    echo "# build-deps a garder en phase avec le stage builder du Dockerfile (gcc/g++/unixodbc-dev/libffi-dev/libpango*)."; \
	    echo "# torch est installe separement via lindex CPU par le Dockerfile -> exclu ici."; \
	    pip freeze --exclude-editable | grep -viE "^torch(==| @)"; } > requirements.lock'
	@printf "$(GREEN)+ requirements.lock généré (fidèle au builder). Vérifier (git diff) puis committer pour un build reproductible.$(RESET)\n"

refresh-litellm: ## [MAINT] Rafraîchit la baseline pricing LiteLLM embarquée (réseau requis ; à lancer périodiquement / en CI avant un build client offline)
	@printf "$(GREEN)-> Rafraîchissement de la baseline LiteLLM (pricing offline)...$(RESET)\n"
	@$(VENV)/bin/python -m scripts.refresh_litellm_cache
	@printf "$(YELLOW)! Commiter app/services/ai/data/litellm_registry.json si le diff est attendu.$(RESET)\n"

sync-from-appfazia: ## [MAINT] Sync un repo client depuis appfazia (à lancer DEPUIS LE REPO CLIENT)
	@if [ "$$(cd "$(APPFAZIA_PATH)" 2>/dev/null && pwd)" = "$$(pwd)" ]; then \
	  printf "$(RED)X Tu es dans le repo source — cette cible n'a de sens que dans un repo CLIENT.$(RESET)\n"; \
	  printf "   Pour générer un nouveau repo client : make generate-client-repo DEST=../client-X\n"; \
	  exit 1; \
	fi
	@if [ ! -d "$(APPFAZIA_PATH)" ]; then \
	  printf "$(RED)X Repo source introuvable : $(APPFAZIA_PATH)$(RESET)\n"; \
	  printf "   Override : make sync-from-appfazia APPFAZIA_PATH=/chemin/vers/appfazia\n"; \
	  exit 1; \
	fi
	@printf "$(YELLOW)! Cette opération va ÉCRASER les fichiers de ce repo client$(RESET)\n"
	@printf "$(YELLOW)  avec ceux de %s (sauf .env, .git/, data/, backups/, etc.)$(RESET)\n" "$(APPFAZIA_PATH)"
	@printf "  Vos modifications locales NON commitées seront PERDUES.\n"
	@printf "Tape 'SYNC' pour confirmer : "
	@read CONFIRM; if [ "$$CONFIRM" != "SYNC" ]; then printf "$(YELLOW)Annulé.$(RESET)\n"; exit 1; fi
	@printf "$(GREEN)-> Synchronisation depuis $(APPFAZIA_PATH) (whitelist)...$(RESET)\n"
	@rsync -av --delete \
	  --exclude='__pycache__' \
	  --exclude='*.pyc' \
	  --exclude='*.pyo' \
	  --exclude='.mypy_cache' \
	  --exclude='.pytest_cache' \
	  --exclude='node_modules' \
	  --exclude='.DS_Store' \
	  --include='/.dockerignore' \
	  --include='/.gitignore' \
	  --include='/.env.example' \
	  --include='/Dockerfile' \
	  --include='/docker-compose.yml' \
	  --include='/Makefile' \
	  --include='/README.md' \
	  --include='/COMMANDES.md' \
	  --include='/start.py' \
	  --include='/requirements.txt' \
	  --include='/requirements.lock' \
	  --include='/VERSION' \
	  --include='/package.json' \
	  --include='/tailwind.config.js' \
	  --include='/pyproject.toml' \
	  --include='/config.yaml' \
	  --include='/config/' \
	  --include='/config/openssl_legacy.cnf' \
	  --include='/app/***' \
	  --include='/templates/***' \
	  --include='/static/***' \
	  --include='/scripts/' \
	  --include='/scripts/__init__.py' \
	  --include='/scripts/db_init.py' \
	  --include='/scripts/seed_admin.py' \
	  --include='/scripts/pipeline.py' \
	  --include='/scripts/prefetch_models.py' \
	  --include='/scripts/preflight.py' \
	  --include='/scripts/setup_deploy_env.py' \
	  --include='/scripts/setup_host_nginx.py' \
	  --include='/scripts/gen_cert.py' \
	  --include='/scripts/render_nginx_conf.py' \
	  --include='/scripts/renew_cert.py' \
	  --include='/scripts/install_cert_timer.py' \
	  --include='/scripts/vacuum_db.py' \
	  --include='/scripts/scrub_dotenv_value.sh' \
	  --include='/scripts/keycheck.sh' \
	  --include='/deployment/' \
	  --include='/deployment/nginx/' \
	  --include='/deployment/nginx/komptia.conf' \
	  --include='/deployment/systemd/' \
	  --include='/deployment/systemd/komptia-cert-renew.service' \
	  --include='/deployment/systemd/komptia-cert-renew.timer' \
	  --include='/docs/' \
	  --include='/docs/guides/' \
	  --include='/docs/guides/*.pdf' \
	  --exclude='*' \
	  "$(APPFAZIA_PATH)/" ./
	@{ git -C "$(APPFAZIA_PATH)" describe --tags --always --dirty 2>/dev/null || echo "2.0.0"; } > VERSION
	@printf "\n$(GREEN)+ Synchronisation terminée (version stampée dans VERSION).$(RESET)\n"
	@printf "$(YELLOW)! Vérifier les changements : git status && git diff$(RESET)\n"
	@printf "  Tester : make build && make up && make status\n"

generate-client-repo: ## [MAINT] Génère un nouveau repo client : make generate-client-repo DEST=../client-X
	@if [ -z "$(DEST)" ]; then \
	  printf "$(RED)X Usage : make generate-client-repo DEST=../client-X$(RESET)\n"; \
	  exit 1; \
	fi
	@printf '%s' "$(DEST)" | grep -Eq '^[a-zA-Z0-9._/ -]+$$' || { \
	  printf "$(RED)X DEST contient des caractères interdits (autorisés : a-z A-Z 0-9 espace . _ / -)$(RESET)\n"; \
	  exit 1; \
	}
	@if [ -e "$(DEST)" ]; then \
	  printf "$(RED)X $(DEST) existe déjà — refus d'écraser$(RESET)\n"; \
	  printf "   Pour mettre à jour un repo client existant : cd $(DEST) && make sync-from-appfazia\n"; \
	  exit 1; \
	fi
	@set -e; \
	printf "$(GREEN)-> Création du repo client : $(DEST) (whitelist)$(RESET)\n"; \
	mkdir -p "$(DEST)"; \
	rsync -a \
	  --exclude='__pycache__' \
	  --exclude='*.pyc' \
	  --exclude='*.pyo' \
	  --exclude='.mypy_cache' \
	  --exclude='.pytest_cache' \
	  --exclude='node_modules' \
	  --exclude='.DS_Store' \
	  --include='/.dockerignore' \
	  --include='/.gitignore' \
	  --include='/.env.example' \
	  --include='/Dockerfile' \
	  --include='/docker-compose.yml' \
	  --include='/Makefile' \
	  --include='/README.md' \
	  --include='/COMMANDES.md' \
	  --include='/start.py' \
	  --include='/requirements.txt' \
	  --include='/requirements.lock' \
	  --include='/VERSION' \
	  --include='/package.json' \
	  --include='/tailwind.config.js' \
	  --include='/pyproject.toml' \
	  --include='/config.yaml' \
	  --include='/config/' \
	  --include='/config/openssl_legacy.cnf' \
	  --include='/app/***' \
	  --include='/templates/***' \
	  --include='/static/***' \
	  --include='/scripts/' \
	  --include='/scripts/__init__.py' \
	  --include='/scripts/db_init.py' \
	  --include='/scripts/seed_admin.py' \
	  --include='/scripts/pipeline.py' \
	  --include='/scripts/prefetch_models.py' \
	  --include='/scripts/preflight.py' \
	  --include='/scripts/setup_deploy_env.py' \
	  --include='/scripts/setup_host_nginx.py' \
	  --include='/scripts/gen_cert.py' \
	  --include='/scripts/render_nginx_conf.py' \
	  --include='/scripts/renew_cert.py' \
	  --include='/scripts/install_cert_timer.py' \
	  --include='/scripts/vacuum_db.py' \
	  --include='/scripts/scrub_dotenv_value.sh' \
	  --include='/scripts/keycheck.sh' \
	  --include='/deployment/' \
	  --include='/deployment/nginx/' \
	  --include='/deployment/nginx/komptia.conf' \
	  --include='/deployment/systemd/' \
	  --include='/deployment/systemd/komptia-cert-renew.service' \
	  --include='/deployment/systemd/komptia-cert-renew.timer' \
	  --include='/docs/' \
	  --include='/docs/guides/' \
	  --include='/docs/guides/*.pdf' \
	  --exclude='*' \
	  ./ "$(DEST)/"; \
	printf "$(GREEN)-> Stamp version (git describe) dans VERSION...$(RESET)\n"; \
	{ git describe --tags --always --dirty 2>/dev/null || echo "2.0.0"; } > "$(DEST)/VERSION"; \
	printf "$(GREEN)-> git init + commit initial...$(RESET)\n"; \
	cd "$(DEST)" && git init -q -b main && git add . && \
	  git -c user.email="komptia@deploy.local" -c user.name="Komptia Deploy" \
	    commit -q -m "Initial deployment: Komptia ready for first-run"; \
	printf "\n$(GREEN)+ Repo client créé : $(DEST)$(RESET)\n"; \
	printf "  Taille : $$(du -sh "$(DEST)" | cut -f1) — Fichiers : $$(find "$(DEST)" -type f | wc -l | tr -d ' ')\n"; \
	printf "\n  Prochaines étapes :\n"; \
	printf "    cd $(DEST)\n"; \
	printf "    cp .env.example .env\n"; \
	printf "    # éditer .env : générer SECRET_KEY, SQLCIPHER_KEY, remplir SAGE_DB_*, etc.\n"; \
	printf "    make first-run\n"
