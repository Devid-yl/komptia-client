# Plotly (self-hosted)

`plotly-basic.min.js` — version `2.35.2` du build "basic" de Plotly.js.

## Pourquoi self-hosté

Avant : chargé depuis `https://cdn.jsdelivr.net/npm/plotly.js-basic-dist-min@2.35.2/...`.

Problèmes du CDN externe :
- **Resilience** : si jsdelivr est down ou bloqué par un firewall corporate, le dashboard n'a plus de graphiques.
- **Privacy** : chaque visiteur signale au CDN qu'il utilise Komptia.
- **SRI manquant** : sans `integrity="sha384-..."`, un compromis du CDN pourrait injecter un script arbitraire.

Le self-host élimine ces 3 risques. Coût : ~1 MB chargé une fois et caché par le navigateur (Tornado renvoie `Cache-Control: max-age=31536000` par défaut sur les fichiers statiques).

## Mise à jour

```bash
# Récupérer la version désirée :
curl -sL "https://cdn.jsdelivr.net/npm/plotly.js-basic-dist-min@VERSION/plotly-basic.min.js" \
  -o static/vendor/plotly/plotly-basic.min.js

# Mettre à jour ce README avec la nouvelle version.
```

Les templates qui consomment Plotly :
- `templates/dashboard/admin.html`
- `templates/dashboard/user.html`

(chargé via le module `static/js/dashboard-charts.js`).
