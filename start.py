#!/usr/bin/env python3
"""
Script de lancement simplifié Komptia
Usage: python start.py
"""
import sys
import os

# Ajouter le répertoire racine au PYTHONPATH
_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _root)

# Configurer OpenSSL pour autoriser TLS 1.0/1.1 (requis par SQL Server Sage).
# Le fichier vit sous ``config/`` (cohérent avec app/__init__.py et app/main.py
# qui font le vrai bootstrap) — l'ancien chemin racine était un no-op silencieux
# car le fichier n'y est jamais.
_openssl_cfg = os.path.join(_root, "config", "openssl_legacy.cnf")
if os.path.exists(_openssl_cfg):
    os.environ.setdefault("OPENSSL_CONF", _openssl_cfg)

# Importer et lancer l'application
if __name__ == "__main__":
    try:
        print("🚀 Démarrage Komptia...")
        print(f"📁 Répertoire: {os.getcwd()}")
        print(f"🐍 Python: {sys.version}")
        
        # Importer le main
        from app import main
        
        # Lancer l'application
        main.main()
        
    except KeyboardInterrupt:
        print("\n⛔ Arrêt demandé par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
