# Drawflow (vendored)

Canvas library for DAG editor UI (Phase 3b Komptia).

- **Version** : 0.0.60
- **Licence** : MIT (voir https://github.com/jerosoler/Drawflow)
- **Source** : `https://unpkg.com/drawflow@0.0.60/dist/`
- **Vendored** : 2026-04-24

## Intégrité (SHA-256)

Vérifier que les fichiers vendored n'ont pas été altérés — recalculer et
comparer après tout `curl` de mise à jour ou changement suspect.

| Fichier | SHA-256 |
|---------|---------|
| `drawflow.min.js` | `caf8c4f15b75e27169632ed2122715e52aeb5930b9adca6f519bd82a485a31e2` |
| `drawflow.min.css` | `57e5b37f72d95f97597263f17ef0ae9f0a0cd7b966e039b9f43508040d5dedf2` |

Commande de vérification (macOS / Linux) :

```bash
shasum -a 256 drawflow.min.js drawflow.min.css
# Doit matcher les hashes ci-dessus à l'octet près.
```

Si un hash ne matche plus, NE PAS merger — soit un bug de download, soit
une compromission de la supply-chain (voir https://docs.npmjs.com/about-
supply-chain-security pour contexte).

## Pourquoi vendoring plutôt que CDN

- CSP strict (nonces sur scripts) — plus simple avec fichiers locaux
- Pas de dépendance réseau au runtime
- Reproductibilité du build
- Intégrité vérifiable via SHA-256 (ci-dessus)

## Mettre à jour la version

```bash
curl -sSL -o drawflow.min.js https://unpkg.com/drawflow@X.Y.Z/dist/drawflow.min.js
curl -sSL -o drawflow.min.css https://unpkg.com/drawflow@X.Y.Z/dist/drawflow.min.css
shasum -a 256 drawflow.min.js drawflow.min.css
```

Puis mettre à jour la version + hashes ci-dessus, commit, et tester le
canvas avant merge.

## Adaptations Komptia

Drawflow charge un singleton global `window.Drawflow`. Le code Komptia :
- Utilise `new Drawflow(container)` pour instancier
- Enveloppe le canvas dans un `RendererAdapter` (voir `static/js/automation-canvas.js`)
- Le modèle (`WorkflowDocument`) est découplé du renderer — si on migre
  vers React Flow / LiteGraph plus tard, seul l'adapter change.
