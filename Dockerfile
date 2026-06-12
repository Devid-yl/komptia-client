# =================================================
# Dockerfile - Komptia v2.0
# Multi-stage build pour production
# =================================================

# ── Stage 1: Builder ────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Dépendances système pour la compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    unixodbc-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.lock ./
# PyTorch CPU-only (serveur sans GPU) : sentence-transformers tire `torch` en
# dépendance, et la roue PyPI par défaut embarque ~6 Go de paquets CUDA (cuDNN,
# cuBLAS, nvidia-*) inutiles sur un serveur sans carte NVIDIA — et qui saturent
# le disque (incident 2026-05-29 : "No space left on device" sur VM 17 Go). On
# installe d'abord le wheel CPU depuis l'index PyTorch dédié, PUIS le reste des
# dépendances en pointant PYTHONPATH vers /install pour que pip voie ce torch
# déjà présent ("Requirement already satisfied") et ne le remplace pas par CUDA.
# --timeout 300 + --retries 10 : tolérer les réseaux lents.
RUN pip install --no-cache-dir --prefix=/install --timeout 300 --retries 10 \
    torch --index-url https://download.pytorch.org/whl/cpu
# PYVER dérivé dynamiquement (pas de "3.12" hardcodé) : si l'image de base change
# de version Python, le chemin reste correct. Sinon pip ne verrait plus le torch
# CPU déjà installé et réinstallerait la variante CUDA (retour du bug disque plein).
# requirements.lock (si pins effectifs) → install reproductible ; sinon fallback
# requirements.txt (le lock est un placeholder commentaire-seul par défaut → 0
# changement). torch déjà installé (CPU) ci-dessus, exclu du lock.
RUN set -e; \
    PYVER="$(python -c 'import sys;print("%d.%d"%sys.version_info[:2])')"; \
    if grep -qvE '^[[:space:]]*(#|$)' requirements.lock 2>/dev/null; then \
      echo "[build] requirements.lock effectif -> install reproductible (versions figées)"; \
      REQFILE=requirements.lock; \
    else \
      echo "[build] requirements.lock vide -> install depuis requirements.txt"; \
      REQFILE=requirements.txt; \
    fi; \
    PYTHONPATH="/install/lib/python${PYVER}/site-packages" \
      pip install --no-cache-dir --prefix=/install --timeout 300 --retries 10 -r "$REQFILE"


# ── Stage 2: Production ────────────────────────
FROM python:3.12-slim AS production

# Métadonnées
LABEL org.opencontainers.image.title="Komptia"
LABEL org.opencontainers.image.description="Plateforme d'automatisation et d'analyse de données SQL Server"
LABEL org.opencontainers.image.version="2.0"

# Dépendances runtime (pas de compilateurs).
# libgomp1 = OpenMP, requis par scikit-learn/scipy (transitifs de
# sentence-transformers) — absent de python:3.12-slim. Sans lui : ImportError
# "libgomp.so.1" → le prefetch casse au build + embeddings KO au runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    unixodbc \
    libgomp1 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    fonts-liberation \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r komptia && useradd -r -g komptia -d /opt/komptia komptia

# Microsoft ODBC Driver 18 for SQL Server — REQUIS pour que pyodbc puisse
# parler à la base source. `unixodbc` ci-dessus n'est QUE le gestionnaire de
# drivers (coquille vide) : sans ce paquet, `pyodbc.drivers()` ne liste aucun
# "ODBC Driver 18 for SQL Server" → `discover_sage_odbc_driver()` lève
# `SageDriverMissingError` → TOUTE connexion BDD échoue. C'est exactement
# l'incident prod où le client voyait « erreur réseau/auth » alors que le driver
# manquait dans l'image (il était installé sur le Mac de dev via `brew`, jamais
# dans le conteneur). Version Debian dérivée dynamiquement de /etc/os-release
# (pas de "12" hardcodé) pour suivre l'image de base si elle change de release.
# `packages-microsoft-prod.deb` enregistre la clé GPG + le dépôt apt Microsoft ;
# `ACCEPT_EULA=Y` est obligatoire pour msodbcsql18.
# curl est déjà présent (installé dans le RUN runtime ci-dessus) → pas réinstallé.
# ca-certificates est déjà dans python:3.x-slim ; gnupg est inutile (la clé est
# posée par le .deb et apt vérifie via gpgv intégré). On ne réinstalle donc rien.
# `curl -fsSL` (--fail) : sur un HTTP 404 (release Debian non publiée par MS, ex.
# une future trixie) curl SANS -f écrirait la page d'erreur HTML dans le .deb et
# retournerait 0 → `dpkg -i` planterait avec « not a Debian format archive », un
# diagnostic opaque. -f fait échouer curl proprement avec un message actionnable.
# (Pas de `file` : absent de l'image slim ; dpkg rejette de toute façon un .deb
# corrompu, et le guard pyodbc plus bas est le filet final.)
RUN set -e; \
    . /etc/os-release; \
    curl -fsSL -o /tmp/ms-prod.deb \
      "https://packages.microsoft.com/config/debian/${VERSION_ID}/packages-microsoft-prod.deb" \
      || { echo "ERREUR build: packages-microsoft-prod.deb introuvable pour Debian ${VERSION_ID} — release non publiee par Microsoft. Epingler une base Debian supportee (ex. bookworm/12) ou utiliser un miroir interne." >&2; exit 1; }; \
    dpkg -i /tmp/ms-prod.deb; \
    rm -f /tmp/ms-prod.deb; \
    apt-get update; \
    ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18; \
    rm -rf /var/lib/apt/lists/*

# Copier les dépendances Python du builder
COPY --from=builder /install /usr/local

# Garde-fou « costume sans corps » : échouer BRUYAMMENT au build si pyodbc ne
# voit aucun des drivers SQL Server ATTENDUS par le runtime (msodbcsql18 mal
# installé, ou dépôt MS absent pour cette release Debian). Sans ce garde, l'image
# se construirait « verte » puis toute connexion BDD casserait au runtime chez le
# client — la classe de bug que ce fix élimine. On exige les noms EXACTS que
# `discover_sage_odbc_driver()` recherche (Driver 17 préféré, sinon 18), pas un
# simple substring « SQL Server » (qui matcherait un driver tiers ou une entrée
# orpheline d'odbcinst.ini). pyodbc est importable ici (copié juste au-dessus) et
# lit /etc/odbcinst.ini renseigné par msodbcsql18.
# NB : ce garde couvre la PRÉSENCE du driver. La connexion aux SQL Server anciens
# (TLS 1.0/1.1) dépend EN PLUS de config/openssl_legacy.cnf, gardé séparément
# plus bas (COPY config/) — les deux conditions sont nécessaires au runtime.
RUN python -c "import pyodbc, sys; d = pyodbc.drivers(); expected = {'ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server'}; sys.stderr.write('ODBC drivers: %r\n' % (d,)); sys.exit(0 if expected.intersection(d) else 1)" \
    || { echo 'ERREUR build: aucun driver ODBC SQL Server attendu (17/18) visible par pyodbc (msodbcsql18 absent) — la connexion a la base source casserait au runtime' >&2; exit 1; }

# Garde-fou « costume sans corps » SQLCipher : échouer BRUYAMMENT au build si
# sqlcipher3 n'est pas fonctionnel (wheel manquant pour la plateforme, ou moteur
# non-SQLCipher). Sans ce garde, l'image se construirait « verte » puis l'app
# refuserait de booter dès qu'une SQLCIPHER_KEY est posée (fail-closed
# setup_encryption), exactement la classe de bug que ce fix élimine. On exige un
# cipher_version non vide commençant par « 4 » (SQLCipher 4.x). sqlcipher3 est
# importable ici (copié via /install ci-dessus) si présent dans requirements.
RUN python -c "import sqlcipher3.dbapi2 as s, sys; v=(s.connect(':memory:').execute('PRAGMA cipher_version').fetchone() or [None])[0]; sys.stderr.write('SQLCipher cipher_version=%r\n' % (v,)); sys.exit(0 if v and str(v).startswith('4') else 1)" \
    || { echo 'ERREUR build: sqlcipher3 absent ou non fonctionnel (cipher_version vide) — le chiffrement BDD casserait au runtime (fail-closed). Verifier le wheel manylinux sqlcipher3 pour cette plateforme.' >&2; exit 1; }

WORKDIR /opt/komptia

# Copier le code applicatif
COPY app/ app/
COPY scripts/ scripts/
COPY templates/ templates/
COPY static/ static/
COPY config.yaml .
COPY start.py .
# Version applicative (stampée par generate-client-repo/sync via git describe) →
# lue par config.app_version, exposée sur /health/detailed.
COPY VERSION .

# Config OpenSSL legacy (TLS 1.0/1.1) — requise quand le SQL Server source
# (profil Sage Coala) parle un protocole que le Driver 18 + OpenSSL 3.x refuse
# par défaut. Vit sous config/ (HORS data/, donc NON masqué par le volume
# komptia-data). Sans elle, app/__init__.py / app/main.py ne posent jamais
# OPENSSL_CONF → handshake refusé → test connexion BDD KO avec un message qui
# blâme à tort le serveur source.
COPY config/ config/

# Garde-fou anti « costume sans corps » : échouer BRUYAMMENT au build si une
# ressource read-only livrée-avec-le-code et lue au RUNTIME manque de l'image
# (data/ exclu + volume vide = piège récurrent, cf. precedent docs/guides).
# `set -e` + un guard explicite par ressource (plus robuste qu'un chaînage
# &&/|| dont la précédence shell est piégeuse).
RUN set -e; \
    test -f config/openssl_legacy.cnf \
      || { echo 'ERREUR build: config/openssl_legacy.cnf absent — TLS legacy SQL Server casse' >&2; exit 1; }; \
    test -f scripts/pipeline.py \
      || { echo 'ERREUR build: scripts/pipeline.py absent — coeur NL->SQL Iris (run_pipeline/mutate_last_ir) casse' >&2; exit 1; }; \
    test -n "$(ls app/services/automation/templates/*.json 2>/dev/null)" \
      || { echo 'ERREUR build: aucun template automation embarque — galerie /automations/templates vide' >&2; exit 1; }; \
    test -n "$(ls app/services/reporting/templates/*.json 2>/dev/null)" \
      || { echo 'ERREUR build: aucun template de rapport embarque — galerie /templates (rapports predefinis) vide' >&2; exit 1; }; \
    test -f app/services/ai/data/analytical_patterns.yaml \
      || { echo 'ERREUR build: analytical_patterns.yaml absent — Iris perd ses motifs analytiques' >&2; exit 1; }; \
    test -s app/services/ai/data/litellm_registry.json \
      || { echo 'ERREUR build: baseline LiteLLM absente — pricing 0$ silencieux sur client offline (lancer scripts/refresh_litellm_cache.py)' >&2; exit 1; }

# Guides d'utilisation PDF (par rôle) servis dans /settings → Aide. Contenu en
# LECTURE SEULE embarqué dans l'image (hors volume /opt/komptia/data) → présent
# dès le premier démarrage chez un nouveau client, sans génération côté serveur.
# Atterrit dans /opt/komptia/docs/guides/ = config.guides_dir (BASE_DIR/docs/guides).
# Whitelisté dans .dockerignore (docs/guides/*.pdf uniquement).
COPY docs/guides/ docs/guides/

# Garde-fou anti « costume sans corps » : échouer BRUYAMMENT au build si AUCUN
# guide PDF n'a été embarqué, plutôt que de livrer une section Aide vide en prod.
# (Le COPY ci-dessus réussit même sur un dossier présent mais vide — il ne plante
# que si la source est totalement absente.) Côté dev : `make guides` avant le build ;
# côté repo client : les .pdf sont rsyncés par make sync-from-appfazia/generate-client-repo.
RUN test -n "$(ls docs/guides/*.pdf 2>/dev/null)" \
    || (echo 'ERREUR build: aucun guide PDF dans docs/guides/ — lancer `make guides` avant le build' >&2 && exit 1)

# Cache des modèles d'embeddings — le MODÈLE n'est PAS embarqué dans l'image
# (image légère). ``HF_HOME`` pointe SOUS le volume de données : le modèle (~440 Mo)
# est pré-téléchargé AU DÉPLOIEMENT par ``make first-run``/``make reset`` (étape
# ``_prefetch-models`` → ``scripts.prefetch_models`` dans le conteneur) pour qu'il
# soit prêt AVANT le 1er usage Iris, puis PERSISTE dans le volume (pas de re-download
# à chaque recreate). Repli gracieux : si le serveur est hors-ligne au déploiement,
# ``EmbeddingService`` re-tente le download À LA DEMANDE au 1er usage et dégrade en
# TF-IDF entre-temps (les embeddings ne bloquent jamais Iris). Sur serveur isolé,
# ``make prefetch-models`` relance le téléchargement une fois le réseau rétabli.
ENV HF_HOME=/opt/komptia/data/hf_cache

# Caches de polices SOUS le volume → matplotlib (``MPLCONFIGDIR``) et fontconfig
# (``XDG_CACHE_HOME``) ne RECONSTRUISENT PAS leur cache à chaque recreate du
# conteneur (sinon log « Matplotlib building the font cache » + 1er PDF/graphe
# lent à chaque ``make update``). Les libs créent ces dossiers au runtime si
# absents ; le ``mkdir`` ci-dessous fixe les perms komptia pour une install
# fraîche. HF garde son propre ``HF_HOME`` ci-dessus (pas via XDG_CACHE_HOME).
ENV MPLCONFIGDIR=/opt/komptia/data/.mpl-cache
ENV XDG_CACHE_HOME=/opt/komptia/data/.cache

# Répertoires de données (créés dans l'image → leurs perms komptia sont copiées
# vers le volume au 1er montage, dont ``hf_cache`` pour que le download runtime
# soit autorisé). Pas de ``HF_HUB_OFFLINE=1`` : le runtime DOIT pouvoir télécharger
# le modèle à la demande (sinon TF-IDF en repli).
RUN mkdir -p data/logs data/reports data/backups data/hf_cache \
        data/.mpl-cache data/.cache \
    && chown -R komptia:komptia /opt/komptia

# Variables d'environnement par défaut
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENVIRONMENT=production
ENV DEBUG=false

# ── Empreinte mémoire (glibc / torch-BLAS) ────────────────────────────────────
# Image python:3.12-slim = glibc → ces variables s'appliquent (no-op sur musl).
# MALLOC_ARENA_MAX=2 : borne le nombre d'arènes glibc (défaut = 8×nbCPU) qui,
#   avec torch/numpy/BLAS multi-thread, gonfle le RSS par fragmentation.
# MALLOC_TRIM_THRESHOLD_=131072 : rend la mémoire libérée à l'OS (128 KiB) au lieu
#   de la conserver dans le heap après un pic transitoire (gros résultat SQL).
# OMP/MKL/OPENBLAS_NUM_THREADS=2 : les embeddings sont des appels courts batchés ;
#   cap les threads (et leurs stacks) que torch/BLAS spawneraient sinon (= nbCPU).
ENV MALLOC_ARENA_MAX=2
ENV MALLOC_TRIM_THRESHOLD_=131072
ENV OMP_NUM_THREADS=2
ENV MKL_NUM_THREADS=2
ENV OPENBLAS_NUM_THREADS=2

# Passer à l'utilisateur non-root
USER komptia

# Port Tornado
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Démarrage via start.py (charge openssl_legacy.cnf si présent — TLS legacy SQL Server)
CMD ["python", "start.py"]
