# Chart.js (self-hosted)

`chart.umd.min.js` — Chart.js v4.4.1, build UMD min.

## Pourquoi self-hosté (Bug 2026-05-26 P-8 MOYEN)

Avant : chargé depuis `https://cdn.jsdelivr.net/npm/chart.js` (sans version
pinnée, sans SRI).

Problèmes du CDN externe :

- **Resilience** : si jsdelivr est down ou bloqué par un firewall corporate
  (cabinet comptable derrière proxy strict), le dashboard `/admin/performance`
  et `/admin/ai-performance` perdent leurs graphiques.
- **Privacy** : chaque visiteur signale à jsdelivr qu'il utilise Komptia.
  Pour un cabinet comptable manipulant des données financières, c'est un
  signal de surface inutile.
- **SRI manquant** : sans `integrity="sha384-..."`, un compromis du CDN
  pourrait injecter un script arbitraire avec les permissions de
  `/admin/performance` (admin only mais sensible).
- **Version flottante** : `npm/chart.js` (sans `@<version>`) résout en
  fait au "latest" — un breaking change Chart.js 5 casserait la prod
  silencieusement.

Le self-host élimine ces 4 risques. Coût : ~200 KB chargé une fois et caché
par le navigateur (Tornado renvoie `Cache-Control: max-age=31536000` par
défaut sur les fichiers statiques).

## Mise à jour

```bash
# Récupérer la version désirée :
curl -sL "https://cdn.jsdelivr.net/npm/chart.js@VERSION/dist/chart.umd.min.js" \
  -o static/vendor/chartjs/chart.umd.min.js

# Mettre à jour ce README avec la nouvelle version.
```

Source officielle : <https://www.chartjs.org/docs/latest/>.
