"""
Helpers pour les templates Tornado.
Permet de convertir les dicts en objets pour accès via notation pointée,
tout en restant pleinement compatibles avec json.dumps / tornado.escape.json_encode.
"""


class DictObject(dict):
    """Dict-subclass qui permet l'accès en notation pointée (``obj.key``)
    tout en restant ``isinstance(obj, dict) == True`` (et donc JSON-sérialisable).

    - ``obj.key`` / ``obj['key']`` / ``obj.get('key')`` fonctionnent.
    - Les valeurs dict/list imbriquées sont également wrappées récursivement.
    - Les clés qui collisionnent avec des méthodes dict (``items``, ``keys``,
      ``values``, ``get``…) restent accessibles via ``obj.key`` grâce au
      stockage miroir dans ``__dict__`` — l'attribut d'instance l'emporte
      sur la méthode héritée.
    - Les scalaires (chaîne, nombre) restent supportés via le wrapper ``_value``
      pour compat rétro-active.
    """

    def __init__(self, data=None):
        super().__init__()
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    wrapped = DictObject(value)
                elif isinstance(value, list):
                    wrapped = [
                        DictObject(item) if isinstance(item, dict) else item for item in value
                    ]
                else:
                    wrapped = value
                self[key] = wrapped
                # Miroir dans __dict__ : garantit que `obj.key` gagne contre les
                # méthodes de dict (items/keys/values/get/…) quand une clé porte
                # ce nom.
                object.__setattr__(self, str(key), wrapped)
        elif data is not None:
            object.__setattr__(self, "_value", data)

    def __getattr__(self, key):
        """Appelé uniquement si la recherche d'attribut normale échoue."""
        try:
            return self[key]
        except KeyError:
            raise AttributeError(f"'DictObject' has no attribute {key!r}")

    def __setattr__(self, key, value):
        # Les clés "privées" (commençant par _) ne vont que dans __dict__ et
        # restent invisibles côté JSON — utile pour _value.
        if isinstance(key, str) and key.startswith("_"):
            object.__setattr__(self, key, value)
            return
        self[key] = value
        object.__setattr__(self, str(key), value)

    def __repr__(self):
        val = self.__dict__.get("_value")
        if val is not None and len(self) == 0:
            return repr(val)
        return f"DictObject({dict(self)})"

    def __bool__(self):
        val = self.__dict__.get("_value")
        if val is not None:
            return bool(val)
        return len(self) > 0


def to_dict_object(data):
    """
    Convertit un dict ou une liste de dicts en DictObject pour utilisation dans templates.

    Args:
        data: Dict, liste, ou autre type

    Returns:
        DictObject si dict, liste de DictObject si liste de dicts, sinon valeur originale
    """
    if isinstance(data, DictObject):
        return data
    if isinstance(data, dict):
        return DictObject(data)
    if isinstance(data, list):
        return [DictObject(item) if isinstance(item, dict) else item for item in data]
    return data
