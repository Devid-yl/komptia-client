"""Core partagé des outils plan_add / plan_update / plan_list.

Utilisé à la fois par :
- ``copilot_tools.handle_plan_*`` (state porté par ``CopilotContext.plan``)
- ``agent_tools._handle_plan_*`` (state porté par ``context["plan"]``)

Single source of truth pour la validation et la mutation du plan. Aucune
I/O, aucun logger, aucun état global. La persistance (sync vers
``copilot_progress_store``) et l'émission WebSocket restent du ressort
des callers — ce module ne s'occupe que de la cohérence du plan en
mémoire.

Caps :
- ``MAX_PLAN_TASKS`` (50) : protège contre une boucle LLM qui empilerait
  des tasks sans jamais les compléter (axe 21 Komptia — pas de croissance
  non bornée).
- ``MAX_SUBJECT_LEN`` (200) / ``MAX_DESCRIPTION_LEN`` (500) : protège la
  largeur des chips dans l'UI et le coût tokens des replays.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


PLAN_STATUSES: Tuple[str, ...] = ("pending", "in_progress", "completed", "cancelled")
MAX_PLAN_TASKS: int = 50
MAX_SUBJECT_LEN: int = 200
MAX_DESCRIPTION_LEN: int = 500


def add_task(
    plan: List[Dict[str, Any]],
    next_id: int,
    subject: Any,
    description: Any = None,
) -> Tuple[bool, Optional[Dict[str, Any]], int, Optional[str]]:
    """Valide les inputs et append une task au plan.

    Retourne ``(ok, task, next_id_apres, erreur)`` :
    - succès : ``(True, task_dict, next_id + 1, None)`` et ``plan`` est muté.
    - échec : ``(False, None, next_id, message)`` et ``plan`` est inchangé.
    """
    if not isinstance(subject, str) or not subject.strip():
        return (False, None, next_id, "`subject` requis (string non-vide).")
    if description is not None and not isinstance(description, str):
        return (False, None, next_id, "`description` doit être string si fourni.")
    if len(plan) >= MAX_PLAN_TASKS:
        return (
            False,
            None,
            next_id,
            f"plan plein (max {MAX_PLAN_TASKS} tasks). "
            "Marque les tasks obsolètes en `cancelled` ou `completed` avant d'en ajouter.",
        )

    subject_clean = subject.strip()
    if len(subject_clean) > MAX_SUBJECT_LEN:
        subject_clean = subject_clean[:MAX_SUBJECT_LEN]

    task: Dict[str, Any] = {
        "id": next_id,
        "subject": subject_clean,
        "status": "pending",
        # Timestamp monotone — utilisé par les UIs pour identifier la task
        # in_progress la plus récemment activée (pas juste la dernière insérée).
        "updated_at": time.time(),
    }
    if description is not None:
        desc_clean = description.strip()
        if desc_clean:
            if len(desc_clean) > MAX_DESCRIPTION_LEN:
                desc_clean = desc_clean[:MAX_DESCRIPTION_LEN]
            task["description"] = desc_clean

    plan.append(task)
    return (True, task, next_id + 1, None)


def update_task(
    plan: List[Dict[str, Any]],
    task_id: Any,
    status: Any = None,
    subject: Any = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Met à jour le status et/ou le subject d'une task existante.

    Retourne ``(ok, task, erreur)`` — sur succès ``task`` est le dict muté
    (toujours référencé dans ``plan``).

    Rejette explicitement ``bool`` (Python: ``isinstance(True, int) is True``)
    et ``task_id <= 0``. ``updated_at`` n'est refresh que si une valeur
    change effectivement — un ``plan_update`` qui repasse le même status
    ne modifie pas le timestamp.
    """
    if isinstance(task_id, bool) or not isinstance(task_id, int) or task_id < 1:
        return (False, None, "`task_id` requis (integer ≥ 1, pas bool).")
    if status is not None and status not in PLAN_STATUSES:
        return (
            False,
            None,
            f"`status` invalide ({status!r}). Valeurs acceptées : {list(PLAN_STATUSES)}.",
        )
    if subject is not None and (not isinstance(subject, str) or not subject.strip()):
        return (False, None, "`subject` doit être string non-vide si fourni.")

    for task in plan:
        if task.get("id") == task_id:
            mutated = False
            if status is not None and task.get("status") != status:
                task["status"] = status
                mutated = True
            if subject is not None:
                subject_clean = subject.strip()
                if len(subject_clean) > MAX_SUBJECT_LEN:
                    subject_clean = subject_clean[:MAX_SUBJECT_LEN]
                if task.get("subject") != subject_clean:
                    task["subject"] = subject_clean
                    mutated = True
            if mutated:
                task["updated_at"] = time.time()
            return (True, task, None)

    return (False, None, f"task_id {task_id} introuvable dans le plan.")


def list_plan(plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Snapshot du plan avec décompte par status."""
    return {
        "tasks": [dict(t) for t in plan],
        "total": len(plan),
        "by_status": {s: sum(1 for t in plan if t.get("status") == s) for s in PLAN_STATUSES},
    }


def snapshot(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Copie défensive pour émission WebSocket ou persistance.

    ``updated_at`` est strippé : il est utile en interne (la copilot s'en
    sert pour le miroir « task in_progress la plus récemment activée »)
    mais l'UI Iris ne le lit pas, et le laisser dans le snapshot pollue
    chaque WS event avec un float wall-clock qui peut diverger si l'horloge
    serveur dérive. On rajoutera le champ si une vraie consommatrice
    frontend apparaît plus tard.
    """
    return [
        {k: v for k, v in t.items() if k != "updated_at"}
        for t in plan
    ]
