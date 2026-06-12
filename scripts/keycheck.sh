#!/bin/sh
# =============================================================================
# Sentinelle de clé SQLCipher — empreinte NON-SECRÈTE (HMAC) de SQLCIPHER_KEY.
# =============================================================================
# But : vérifier « la clé courante (.env) est-elle celle qui a chiffré CE
# volume / CE backup ? » SANS tenter un boot ni exposer la clé. Une divergence
# = la clé n'ouvrira pas la base → on refuse une opération destructrice
# (make restore / make update) AVANT de perdre / bricker les données.
#
# L'empreinte = HMAC-SHA256(SQLCIPHER_KEY, "komptia-keycheck") en hex. Stockée
# dans le volume sous data/.keycheck (écrite par `make first-run` / `make reset`
# via la cible _write-keycheck). Irréversible (on ne peut pas retrouver la clé).
#
# La clé est lue depuis .env et NORMALISÉE par .strip() (cohérent avec
# app.config.DatabaseConfig.encryption_key qui fait os.getenv(...).strip()).
#
# Usage :
#   keycheck.sh compute           -> imprime l'empreinte de la clé courante
#                                    exit 0 si clé présente, 2 si pas de clé
#   keycheck.sh verify <stored>   -> exit 0 si match, 1 si MISMATCH,
#                                    2 si pas de clé OU pas d'empreinte stockée
#                                    (= rien à vérifier, l'appelant décide)
#
# ENV_FILE override le chemin du .env (défaut: .env du cwd).
# =============================================================================
set -eu

ENV_FILE="${ENV_FILE:-.env}"

_read_key() {
    # Tout ce qui suit le premier '=' ; trim leading/trailing whitespace
    # (équivalent du .strip() Python côté config).
    grep -E '^SQLCIPHER_KEY=' "$ENV_FILE" 2>/dev/null | head -1 \
        | sed -E 's/^SQLCIPHER_KEY=//; s/^[[:space:]]+//; s/[[:space:]]+$//'
}

_hmac() {
    # $1 = clé. Sortie : digest hex (dernier champ de la sortie openssl).
    printf '%s' 'komptia-keycheck' | openssl dgst -sha256 -hmac "$1" 2>/dev/null \
        | awk '{print $NF}'
}

KEY="$(_read_key)"

case "${1:-}" in
    compute)
        [ -n "$KEY" ] || exit 2          # mode clair : pas d'empreinte
        FP="$(_hmac "$KEY")"
        [ -n "$FP" ] || { echo "keycheck: openssl indisponible/muet" >&2; exit 3; }
        printf '%s\n' "$FP"
        ;;
    verify)
        STORED="${2:-}"
        [ -n "$KEY" ] || exit 2          # pas de clé = mode clair, rien à vérifier
        [ -n "$STORED" ] || exit 2       # pas d'empreinte stockée = non vérifiable
        FP="$(_hmac "$KEY")"
        [ -n "$FP" ] || { echo "keycheck: openssl indisponible/muet" >&2; exit 3; }
        [ "$FP" = "$STORED" ] && exit 0 || exit 1
        ;;
    active)
        # « Le chiffrement est-il actif ? » = une clé NON-BLANCHE est configurée
        # (mêmes sémantiques que config.py : os.getenv(...).strip() non vide).
        # N'utilise PAS openssl → utilisable comme décideur partout dans le
        # Makefile sans dépendance, en SSoT (remplace les grep '^SQLCIPHER_KEY=.+'
        # qui matchaient à tort une valeur faite uniquement d'espaces).
        # exit 0 = chiffrement actif ; exit 1 = mode clair.
        [ -n "$KEY" ] && exit 0 || exit 1
        ;;
    *)
        echo "usage: keycheck.sh active | compute | verify <stored_fingerprint>" >&2
        exit 3
        ;;
esac
