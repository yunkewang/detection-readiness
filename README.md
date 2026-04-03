# Detection Readiness

A CLI-first tool for assessing whether a Splunk environment is ready to **execute** specific detection use cases — including data presence, field coverage, query mode availability, and Splunk knowledge object dependencies.

## Why Detection Readiness?

Detection engineers and security consultants regularly face the same problem: before writing a single SPL query, they need to know whether the environment can actually support the detection they want to build.

Detection Readiness sits **before** content generation and deployment. It now answers two distinct classes of questions:

**Data readiness** (v0.1):
- Is this environment ready for password spray detection?
- Should this detection use raw SPL or datamodel/tstats?
- What fields or data sources are missing?

**Execution readiness** (v0.2):
- Will this detection actually run, given its Splunk knowledge object dependencies?
- Is the required macro present, and is its definition valid?
- Does the macro reference another macro that is also missing?
- Does the lookup exist, and does its backing file or KV store collection exist?
- Is the eventtype defined, and does its search reference any missing macros?
- Is the MLTK model present?
- Which saved searches must run first?
- Can the SPL run at all, or will it silently fail at runtime?

This is **not** a chatbot, not a Splunk app, and not a generic AI wrapper. It is a structured, deterministic, explainable readiness assessment engine with optional AI narrative enhancements.

## Features

- **Environment profile input** — Describe your Splunk environment in YAML or JSON (data sources, indexes, fields, coverage, query modes, constraints, and now knowledge objects)
- **Detection family assessment** — 7 built-in detection families (password spray, impossible travel, suspicious process execution, email impersonation, lateral movement, data exfiltration, privilege escalation)
- **Sample event field discovery** — Auto-discover fields and coverage from JSON, JSONL, or CSV sample events
- **Deterministic scoring** — Repeatable 0–100 scoring with clear status (ready / partially_ready / not_ready)
- **Human-readable explanations** — Template-based short and detailed reports (no LLM dependency)
- **Machine-readable JSON output** — Structured results for pipelines and integrations
- **Splunk REST live profile generation** — Build baseline profiles including knowledge objects from Splunk management API
- **Knowledge object dependency checking** — Resolve macros (including nested chains), eventtypes, lookups (with backing file verification), MLTK models, and saved searches
- **SPL dependency extraction** — Parse SPL queries to extract macro, lookup, eventtype, datamodel, and MLTK references using practical regex heuristics
- **Dependency-aware scoring** — Missing required dependencies add blockers; missing optional deps add warnings
- **Dependency-annotated SPL generation** — Starter SPL output now includes dependency status comments and a dependency-safe variant
- **Optional AI narrative summaries** — Deterministic fallback + OpenAI-backed summaries (when configured)
- **Extensible** — Add new detection families as YAML files; no code changes needed

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Quick Start

### Assess an environment

```bash
detection-readiness assess-cmd \
  --profile examples/azure_profile.yaml \
  --family password_spray
```

### JSON output

```bash
detection-readiness assess-cmd \
  --profile examples/azure_profile.yaml \
  --family password_spray \
  --output json
```

### List available detection families

```bash
detection-readiness list-families
```

### Validate a profile

```bash
detection-readiness validate-profile --profile examples/azure_profile.yaml
```

### Run datamodel health checks

```bash
detection-readiness check-datamodels --profile examples/azure_profile.yaml
```

### Auto-generate a profile from sample events

```bash
detection-readiness generate-profile \
  --events examples/azure_signin_sample.jsonl \
  --output outputs/generated_profile.yaml \
  --environment-name bluebay_autogen \
  --data-source azure_ad_signin \
  --index bluebay_azure_entra \
  --sourcetype azure:aad:signin \
  --min-coverage 0.6
```

### Discover fields from sample events

```bash
detection-readiness discover-fields \
  --events examples/sample_events/azure_ad_signin.jsonl
```

### Explain a saved result

```bash
detection-readiness explain --input outputs/password_spray_azure.json
```

### Generate starter SPL from an assessment result

```bash
# Standard SPL with dependency annotations
detection-readiness generate-spl \
  --input outputs/password_spray_azure.json \
  --output outputs/password_spray_azure.spl

# Dependency-safe variant (avoids macros/lookups; suitable for triage)
detection-readiness generate-spl \
  --input outputs/password_spray_azure.json \
  --safe
```

### Generate a narrative summary (deterministic or OpenAI-backed)

```bash
detection-readiness summarize \
  --input outputs/password_spray_azure.json \
  --provider deterministic
```

### Auto-generate profile from Splunk REST API metadata

```bash
# Basic (indexes, sourcetypes, datamodels)
detection-readiness generate-live-profile \
  --host splunk.company.local \
  --token "$SPLUNK_BEARER_TOKEN" \
  --output outputs/live_profile.yaml \
  --environment-name customer_live

# With knowledge objects (macros, eventtypes, lookups, saved searches, MLTK)
detection-readiness generate-live-profile \
  --host splunk.company.local \
  --token "$SPLUNK_BEARER_TOKEN" \
  --output outputs/live_profile_full.yaml \
  --environment-name customer_live \
  --include-knowledge-objects
```

## Knowledge Object Dependency Commands (v0.2)

### Check execution dependencies for a detection

```bash
detection-readiness check-dependencies \
  --profile outputs/live_profile_full.yaml \
  --family password_spray
```

Example output:
```
Dependency Check
  Environment : customer_live
  Family      : Password Spray Detection
  Total deps  : 4 (resolved: 2, missing: 1, unhealthy: 1, unknown: 0)

Resolved:
  [+] macro: cim_Authentication_indexes [required]
  [+] lookup: user_baseline [optional]

Missing:
  [!] macro: drop_dm_object_name [REQUIRED]

Unhealthy:
  [~] macro: tstats_summariesonly [REQUIRED]
      Macro chain broken: missing transitive macro(s): cim_summariesonly

One or more required dependencies are missing or unhealthy.
```

### List all knowledge objects in a profile

```bash
# All object types
detection-readiness list-knowledge-objects \
  --profile outputs/live_profile_full.yaml

# Specific type
detection-readiness list-knowledge-objects \
  --profile outputs/live_profile_full.yaml \
  --kind macros
```

### Analyze an SPL file for dependencies

```bash
# Extract only
detection-readiness analyze-spl --spl-file my_detection.spl

# Extract and cross-reference against a profile
detection-readiness analyze-spl \
  --spl-file my_detection.spl \
  --profile outputs/live_profile_full.yaml
```

### Show dependency explanation from a saved result

```bash
detection-readiness explain-dependencies \
  --input outputs/password_spray_azure.json
```

## Environment Profile — Full Schema (v0.2)

```yaml
environment_name: customer_env
data_sources:
  azure_ad_signin:
    indexes: [main_azure]
    sourcetypes: [azure:aad:signin]
    fields:
      user:
        candidates: [UserPrincipalName]
        coverage: 0.95
      src_ip:
        candidates: [ipAddress]
        coverage: 0.91
    query_modes:
      raw: true
      datamodel: false
datamodels:
  authentication:
    available: true
    acceleration_enabled: true
    available_objects: [Authentication.action, Authentication.user]
constraints:
  preserve_original_field_names: true
notes:
  - Customer uses raw searches for Azure detections

# New in v0.2 — populated by --include-knowledge-objects
knowledge_objects:
  macros:
    cim_Authentication_indexes:
      name: cim_Authentication_indexes
      available: true
      app: Splunk_SA_CIM
      definition: "(index=main_azure)"
      depends_on_macros: []
    drop_dm_object_name:
      name: drop_dm_object_name
      available: false
  eventtypes:
    winevent_logon:
      name: winevent_logon
      available: true
      search: "EventCode=4624 OR EventCode=4625"
  lookups:
    user_baseline:
      name: user_baseline
      available: true
      backing_type: csv
      filename: user_baseline.csv
      transform_available: true
      file_available: true
  mltk_models:
    anomaly_detector_v2:
      name: anomaly_detector_v2
      available: false
  saved_searches:
    baseline_user_risk:
      name: baseline_user_risk
      available: true
      is_scheduled: true
  collection_notes:
    - "MLTK models endpoint unavailable; models will not appear in this profile."
```

## Detection Family — Execution Dependencies (v0.2)

Families can now declare knowledge object dependencies:

```yaml
id: password_spray
display_name: Password Spray Detection
description: Detects password spray attacks.

required_data_sources:
  - azure_ad_signin
required_fields_by_source:
  azure_ad_signin: [user, src_ip, result]

preferred_query_mode: datamodel
fallback_query_mode: raw

scoring_weights:
  required_data_source: 25.0
  required_fields: 30.0
  optional_fields: 5.0
  preferred_query_mode: 10.0
  fallback_query_mode: 10.0
  dependency_completeness: 20.0   # 0.0 = not scored (v0.1 default)

# New in v0.2
execution_dependencies:
  required_macros:
    - cim_Authentication_indexes
    - drop_dm_object_name
  optional_macros:
    - tstats_summariesonly
  required_lookups:
    - user_baseline
  optional_mltk_models:
    - anomaly_detector_v2
  required_datamodel_objects:
    - Authentication.action
  # OR: let the engine auto-extract from a starter SPL template
  spl_template: |
    | tstats `summariesonly` count from datamodel=Authentication.Authentication
        where nodename=Authentication.Failed_Authentication
        by Authentication.user Authentication.src
    | `drop_dm_object_name(Authentication)`
    | lookup user_baseline user OUTPUT risk_score

remediation_guidance:
  azure_ad_signin: Onboard Azure AD sign-in logs via the add-on.
  cim_Authentication_indexes: Deploy Splunk_SA_CIM and check macro definitions.
  drop_dm_object_name: Install the Common Information Model add-on.
```

**Backward compatibility**: Families without `execution_dependencies` or with `dependency_completeness: 0.0` (the default) behave exactly as in v0.1. No existing profiles or families need changes.

## What Is Collected from Splunk

When `generate-live-profile --include-knowledge-objects` is used:

| Object type | REST endpoint | Notes |
|---|---|---|
| Macros | `/admin/macros` | Definition, args, app/owner/sharing |
| Eventtypes | `/saved/eventtypes` | Search string, ACL |
| Lookup transforms | `/data/transforms/lookups` | Filename, KV store collection, ACL |
| Lookup table files | `/data/lookup-table-files` | File existence check |
| Saved searches | `/saved/searches` | Search, cron schedule, scheduling |
| MLTK models | `/mltk/models` | Algorithm; endpoint may not exist in all versions |
| Tags | `/search/tags` | Best-effort; partial collection is normal |
| Field aliases | `/data/props/fieldaliases` | Best-effort |

Endpoints that fail are recorded in `knowledge_objects.collection_notes` rather than failing the entire profile collection.

## Dependency Analysis Capabilities

| Dependency type | Detection | Chain resolution | Health checks |
|---|---|---|---|
| Macros | ✓ regex + explicit | ✓ up to depth 8 | Empty def, broken chain |
| Eventtypes | ✓ regex + explicit | — | Empty search, missing macro refs |
| Lookups (CSV) | ✓ regex + explicit | — | Missing transform, missing file |
| Lookups (KV store) | ✓ explicit | — | Transform present; file marked unknown |
| Lookups (external) | ✓ explicit | — | Transform present |
| MLTK models | ✓ regex + explicit | — | Available/absent |
| Saved searches | ✓ regex + explicit | — | Available/absent |
| Datamodel objects | ✓ explicit | — | Via `available_objects` in profile |

### SPL Parser Limitations

The dependency extractor uses regex heuristics, not a full SPL parser:

- Macro argument values are captured but not recursively expanded
- `lookup` command aliases (via `transforms.conf`) cannot be detected from SPL text alone
- `inputcsv`/`outputcsv` are not treated as lookup references
- MLTK `fit`/`apply` detection requires the model name to immediately follow the keyword
- Subsearches nested deep inside `eval` strings are detected on a best-effort basis
- SPL comments using non-standard patterns may interfere with macro detection

## Scoring Design

The scoring engine is deterministic and explainable:

| Factor | Impact |
|---|---|
| Missing required data source | Major penalty (blocker) |
| Required field with low coverage | Warning + partial credit |
| Required field completely missing | Blocker |
| Optional field missing | Warning, no penalty |
| Preferred query mode unavailable | Partial penalty + fallback |
| Neither query mode available | Blocker |
| Missing required macro/eventtype/lookup/model | Blocker |
| Missing optional dependency | Warning |
| Dependency exists but unhealthy (empty def, broken chain) | Blocker or warning |
| Dependency unknown (KO not collected) | Warning, conservative partial credit |
| Dependency chain broken | Blocker with chain trace |
| Conflicting constraints | Adjusts recommendation |

Readiness thresholds (configurable):
- **Ready**: score ≥ 80
- **Partially Ready**: score ≥ 50
- **Not Ready**: score < 50

The `dependency_completeness` scoring weight defaults to `0.0` for all families. Set it to a positive value (e.g., `20.0`) in families that declare `execution_dependencies` to have dependency resolution affect the numeric score.

## Project Structure

```
src/detection_readiness/
  schemas/          # Pydantic models (environment, family, result)
  loaders/          # YAML/JSON file loading and validation
  scoring/          # Deterministic scoring engine
  engine/           # Assessment orchestration
  explain/          # Template-based explanation generation
  dependencies/     # SPL parser and dependency resolver (v0.2)
  integrations/     # Splunk REST client and profile builder
  content_factory/  # SPL generation with dependency annotations
  discovery/        # Sample event field discovery
  cli/              # Typer CLI commands
families/           # Detection family definitions (YAML)
examples/           # Example environment profiles
outputs/            # Example assessment outputs
tests/              # Unit and smoke tests
```

## Adding a Detection Family

Create a YAML file in `families/`:

```yaml
id: my_new_detection
display_name: My New Detection
description: Detects something interesting.
required_data_sources:
  - my_data_source
required_fields_by_source:
  my_data_source:
    - field_a
    - field_b
optional_fields_by_source:
  my_data_source:
    - field_c
preferred_query_mode: datamodel
fallback_query_mode: raw
scoring_weights:
  required_data_source: 30.0
  required_fields: 35.0
  optional_fields: 10.0
  preferred_query_mode: 15.0
  fallback_query_mode: 10.0
  dependency_completeness: 0.0     # set > 0 to score deps
execution_dependencies:
  required_macros: []
  required_lookups: []
remediation_guidance:
  my_data_source: Onboard the data source via the appropriate add-on.
```

No code changes required — the CLI picks up new families automatically.

## Running Tests

```bash
pytest tests/ -v
```

## Current Limitations

- **Splunk REST**: Field-level coverage still requires sample events or manual tuning; only indexes, sourcetypes, datamodels, and knowledge object metadata are collected from the REST API
- **MLTK models**: The REST endpoint (`/mltk/models`) does not exist in all Splunk versions or configurations; failures are gracefully recorded as profile notes rather than errors
- **KV store backing**: KV store collection existence cannot be verified from the lookup transforms endpoint alone; these are marked as "availability not verified"
- **SPL parser**: Regex-based, not a full SPL AST parser; see limitations above
- **Datamodel objects**: Object-level availability requires manually populating `available_objects` in the profile; the resolver cannot verify object existence from the REST API alone
- **Sample event scanning**: No direct Splunk export adapters yet; provide JSON, JSONL, or CSV files
- **AI narratives**: Optional; requires `OPENAI_API_KEY` environment variable
- **No web UI**: By design — this is a CLI-first, pipeline-friendly tool

## Roadmap

- [x] Splunk REST API integration for live environment profiling
- [x] Sample-event-based field discovery (JSON/JSONL-driven coverage inference)
- [x] Datamodel health checks
- [x] Environment profile auto-generation (CLI: `generate-profile`)
- [x] Content factory integration (generate SPL from readiness results)
- [x] AI-generated narrative summaries (optional)
- [x] Additional detection families (lateral movement, data exfiltration, privilege escalation)
- [x] **Knowledge object collection via Splunk REST** (macros, eventtypes, lookups, saved searches)
- [x] **Dependency parsing** (SPL regex extractor for macros, lookups, eventtypes, MLTK, saved searches)
- [x] **Dependency resolution** (checks profile knowledge objects; walks macro chains up to depth 8)
- [x] **Dependency-aware scoring** (blockers/warnings for missing/unhealthy deps)
- [x] **New CLI commands** (`check-dependencies`, `list-knowledge-objects`, `analyze-spl`, `explain-dependencies`)
- [x] **Dependency-annotated SPL generation** (inline comments + dependency-safe variant)
- [ ] Batch assessment across multiple families
- [ ] Profile diffing (compare two environments)
- [ ] MITRE ATT&CK mapping for detection families
- [ ] Splunk-side sample event export helper
- [ ] Interactive profile builder wizard
- [ ] CI/CD integration (readiness gates for detection pipelines)
- [ ] Correlation search and notable action dependency support
- [ ] Risk modifier and ES content object dependency support

## License

MIT
