# Bootstrap Icons (vendored)

Icon font + CSS pour les classes `<i class="bi bi-XXX">` partout dans
l'app (palette canvas, top bars, etc.).

- **Version** : 1.11.3
- **Licence** : MIT (voir https://github.com/twbs/icons/blob/main/LICENSE)
- **Source** : `https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/`
- **Vendored** : 2026-04-25

## Pourquoi vendoring

Avant ce vendoring, l'app utilisait `<i class="bi bi-XXX">` dans des
dizaines de templates SANS jamais charger le font. Resultat : pastilles
colorees vides au centre, icones invisibles partout. Le bug etait
silencieux car les pastilles avaient un fond colore.

Vendoring local + CSP `'self'` evite :
- Dependance reseau au runtime
- Configuration CSP supplementaire (font-src CDN externe)
- Drift de version

## Integrite (SHA-256)

Verifier apres tout `curl` de mise a jour ou changement suspect :

| Fichier | SHA-256 |
|---------|---------|
| `bootstrap-icons.min.css` | `f643d6fe7e679f9de3e16311600c5ef5cd6b098f7a3a8828fcc29255d2b33e62` |
| `fonts/bootstrap-icons.woff2` | `476adf42b40325098fcfa8b36ab3e769186bb4f6ce6a249753e2e1a9c22bf99e` |
| `fonts/bootstrap-icons.woff` | `bb1de989b83970f6f4e54de1cd974c5cba55b73582da5e1b225a6d0edf029483` |

```bash
shasum -a 256 bootstrap-icons.min.css fonts/bootstrap-icons.woff2 fonts/bootstrap-icons.woff
```

## Mettre a jour

```bash
cd static/vendor/bootstrap-icons
curl -sSL -o bootstrap-icons.min.css https://cdn.jsdelivr.net/npm/bootstrap-icons@X.Y.Z/font/bootstrap-icons.min.css
curl -sSL -o fonts/bootstrap-icons.woff2 https://cdn.jsdelivr.net/npm/bootstrap-icons@X.Y.Z/font/fonts/bootstrap-icons.woff2
curl -sSL -o fonts/bootstrap-icons.woff https://cdn.jsdelivr.net/npm/bootstrap-icons@X.Y.Z/font/fonts/bootstrap-icons.woff
shasum -a 256 bootstrap-icons.min.css fonts/bootstrap-icons.woff2 fonts/bootstrap-icons.woff
```

Update version + hashes ci-dessus, commit, et tester l'affichage des
icones avant merge (le moindre 404 sur le woff2 = font font-fallback
vers tofu).
