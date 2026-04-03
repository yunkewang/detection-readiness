# Detection Readiness

A CLI-first tool for assessing whether a Splunk environment is ready to support specific detection use cases.

## Why Detection Readiness?

Detection engineers and security consultants regularly face the same problem: before writing a single SPL query, they need to know whether the environment can actually support the detection they want to build.

Detection Readiness sits **before** content generation and deployment. It answers questions like:

- Is this environment ready for password spray detection?
- Can this customer support Azure AD sign-in detections reliably?
- Should this detection use raw SPL, datamodel/tstats, or a hybrid approach?
- What fields, data sources, or normalization gaps would block detection development?
- What assumptions would need to be made before content generation?

This is **not** a chatbot, not a Splunk app, and not a generic AI wrapper. It is a structured, deterministic, explainable readiness assessment engine.

## Features

- **Environment profile input** — Describe your Splunk environment in YAML or JSON (data sources, indexes, fields, coverage, query modes, constraints)
- **Detection family assessment** — Assess readiness against structured detection families (password spray, impossible travel, suspicious process execution, email impersonation)
- **Deterministic scoring** — Repeatable 0–100 scoring with clear status (ready / partially_ready / not_ready)
- **Human-readable explanations** — Template-based short and detailed reports (no LLM dependency)
- **Machine-readable JSON output** — Structured results for pipelines and integrations
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

### Explain a saved result

```bash
detection-readiness explain --input outputs/password_spray_azure.json
```

## Example Environment Profile

```yaml
environment_name: bluebay
data_sources:
  azure_ad_signin:
    indexes:
      - bluebay_azure_entra
    sourcetypes:
      - azure:aad:signin
    fields:
      user:
        candidates: [UserPrincipalName, user, src_user]
        coverage: 0.95
      src_ip:
        candidates: [ipAddress, src_ip]
        coverage: 0.91
      result:
        candidates: [ResultType, action, status]
        coverage: 0.88
      app:
        candidates: [AppDisplayName, app]
        coverage: 0.84
    query_modes:
      raw: true
      datamodel: false
datamodels:
  authentication:
    available: false
constraints:
  preserve_original_field_names: true
  avoid_datamodel: true
notes:
  - Customer uses raw searches for Azure detections
```

## Example Output

```
Detection Readiness Assessment
  Environment : bluebay
  Detection   : Password Spray Detection
  Score       : 78/100
  Status      : partially_ready
  Strategy    : raw

Warnings:
  ~ Optional field 'user_agent' is missing from data source 'azure_ad_signin'.
  ~ Optional field 'location' is missing from data source 'azure_ad_signin'.
  ~ Preferred query mode 'datamodel' is unavailable; falling back to 'raw'.

Assumptions:
  * Field names will not be normalized; detections must use original field names.
  * Datamodel-based searches are to be avoided per environment constraints.
```

## Project Structure

```
src/detection_readiness/
  schemas/        # Pydantic models (environment, family, result)
  loaders/        # YAML/JSON file loading and validation
  scoring/        # Deterministic scoring engine
  engine/         # Assessment orchestration
  explain/        # Template-based explanation generation
  cli/            # Typer CLI commands
families/         # Detection family definitions (YAML)
examples/         # Example environment profiles
outputs/          # Example assessment outputs
tests/            # Unit and smoke tests
```

## Scoring Design

The scoring engine is deterministic and explainable:

| Factor | Impact |
|---|---|
| Missing required data source | Major penalty (blocker) |
| Required field with low coverage | Major penalty |
| Optional field missing | Minor penalty (warning) |
| Preferred query mode unavailable | Partial penalty + fallback |
| Neither query mode available | Major penalty (blocker) |
| Conflicting constraints | Adjusts recommendation |

Readiness thresholds (configurable):
- **Ready**: score >= 80
- **Partially Ready**: score >= 50
- **Not Ready**: score < 50

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
remediation_guidance:
  my_data_source: Onboard the data source via the appropriate add-on.
```

No code changes required — the CLI picks up new families automatically.

## Running Tests

```bash
pytest tests/ -v
```

## Current Limitations

- No direct Splunk API integration (profiles are manually authored)
- Sample event scanning supports JSON, JSONL, and CSV inputs (no direct Splunk export adapters yet)
- Explanation generation is template-based (no AI narratives)
- No web UI
- Limited to four starter detection families

## Roadmap

- [ ] Splunk REST API integration for live environment profiling
- [x] Sample-event-based field discovery (JSON/JSONL-driven coverage inference)
- [ ] Datamodel health checks
- [x] Environment profile auto-generation (CLI: `generate-profile`)
- [ ] Content factory integration (generate SPL from readiness results)
- [ ] AI-generated narrative summaries (optional)
- [ ] Additional detection families (lateral movement, data exfiltration, etc.)

## License

MIT
