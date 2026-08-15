# AGENTS.md

## Projektbeschreibung

Dieses Repository enthält `fortilib`, eine Python-Bibliothek zur Interaktion mit FortiGate-Firewalls. Das Projekt
modelliert Firewall-Objekte wie Adressen, Policies, Services, Interfaces, Routen und andere FortiGate-Konzepte als
Python-Objekte, die typischerweise über eine API-Schicht mit dem Firewall-Device kommunizieren.

Die Kernlogik liegt in `src/fortilib/`. Tests liegen in `tests/` und beschreiben das erwartete Verhalten der Bibliothek.

## Entwicklungs- und Laufzeitumgebung

- Das Projekt verwendet `uv` für die Entwicklung und Abhängigkeitsverwaltung.
- Tests und ähnliche Laufzeit-Checks werden mit `uv run ...` ausgeführt.
- Beispiel:
    - `uv run pytest`
    - `uv run ruff check`

## Wichtige Architektur-Regel

- Alle API-Objekte und modellierten Datenstrukturen basieren auf Pydantic-Modellen.
- Die gemeinsame Basis liegt in `src/fortilib/base.py` und definiert `FortigateObject`, `FortigateCommentedObject`,
  `FortigateNameIdentifieddObject` und `FortigateColoredObject` als Pydantic-Modelle.
- Wenn neue API-Objekte ergänzt werden, sollten sie mit der bestehenden Pydantic-Architektur konsistent modelliert
  werden.

## Hinweise für Codeänderungen

- Bevor Änderungen an API-Modellen oder Verhalten gemacht werden, die Tests im Blick behalten.
- Beim Arbeiten mit diesem Projekt liegt der Schwerpunkt auf sauberen, validierten Pydantic-Modellen und wenig "magic"
  im API-Layer.
- Neue Funktionen sollten im vorhandenen Stil der Bibliothek ergänzt werden und in den bestehenden Tests bzw. mit neuen
  gezielten Tests abgesichert werden.

## Beispielbefehle

```bash
uv sync
uv run pytest
uv run ruff check
```

## Kurz gesagt

Dies ist ein Python-Projekt mit uv-basierter Entwicklung, Pydantic als Modellierungsbasis für API-Objekte und pytest als
Test-Framework.
