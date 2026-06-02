#!/bin/sh
# scrub_dotenv_value.sh — vide la VALEUR d'une variable dans un fichier dotenv,
# en préservant tout le reste (autres variables, commentaires, ordre).
#
# Usage : scrub_dotenv_value.sh <fichier .env> <NOM_VAR>
#
# Pourquoi : un secret de bootstrap (ex. KOMPTIA_ADMIN_PASSWORD) laissé dans .env
# reste injecté dans l'environnement du conteneur (env_file) → visible via
# `docker inspect`. Après usage (seed du compte admin), on vide sa valeur : la
# LIGNE est conservée (`VAR=`) comme repère de config, mais le secret disparaît.
#
# - Idempotent : un re-run sur une valeur déjà vide est un no-op.
# - awk `index()` (pas sed) → robuste aux valeurs contenant `=`, `/`, `$`,
#   guillemets, etc., et insensible aux métacaractères regex.
# - N'altère JAMAIS un commentaire `# VAR=...` (la ligne ne COMMENCE pas par VAR=).
# - Préserve les permissions restrictives du fichier (typiquement 600).
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <fichier .env> <NOM_VAR>" >&2
  exit 2
fi

FILE="$1"
VAR="$2"

[ -f "$FILE" ] || {
  echo "scrub_dotenv_value: fichier introuvable: $FILE" >&2
  exit 1
}

# Valide le nom de variable (alphanumérique + underscore) — refuse tout ce qui
# pourrait être autre chose qu'un identifiant dotenv. Fail-closed.
case "$VAR" in
  "" | *[!A-Za-z0-9_]*)
    echo "scrub_dotenv_value: nom de variable invalide: '$VAR'" >&2
    exit 2
    ;;
esac

tmp=$(mktemp "${FILE}.scrub.XXXXXX")
# Toute ligne qui COMMENCE par `VAR=` (assignation, pas un commentaire `# VAR=`)
# voit sa valeur vidée. ``index($0, v "=") == 1`` = le motif est au tout début.
awk -v v="$VAR" '
  index($0, v "=") == 1 { print v "="; next }
  { print }
' "$FILE" >"$tmp"

# Préserve les perms du .env. `--reference` = GNU coreutils (Linux prod) ;
# fallback 600 pour BSD/macOS (dev) où l'option n'existe pas.
chmod --reference="$FILE" "$tmp" 2>/dev/null || chmod 600 "$tmp"
mv "$tmp" "$FILE"
