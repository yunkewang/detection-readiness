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
- **Detection family assessment** — 7 built-in detection families (password spray, impossible travel, suspicious process execution, email impersonation, lateral movement, data exfiltration, privilege escalation)
- **Deterministic scoring** — Repeatable 0-100 scoring with clear status (ready / partially_ready / not_ready)
- **Human-readable explanations** — Template-based short and detailed reports
- **Machine-readable JSON output** — Structured results for pipelines and integrations
- **Sample event field discovery** — Auto-discover fields and coverage from JSON, JSONL, or CSV sample events
- **Environment profile auto-generation** — Generate profiles from sample events or live Splunk instances
- **SPL content factory** — Generate starter SPL queries based on assessment results and recommended strategy
- **Splunk REST API client** — Connect to live Splunk instances for field summaries and datamodel health checks
- **Datamodel health checks** — Verify datamodel existence, acceleration status, and event counts
- **AI narrative summaries** — Optional AI-powered narrative explanations via Anthropic or OpenAI APIs
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

### Explain a saved result

```bash
detection-readiness explain --input outputs/password_spray_azure.json
```

### Discover fields from sample events

```bash
detection-readiness discover-fields \
  --events examples/sample_events/azure_ad_signin.jsonl
```

### Auto-generate an environment profile

```bash
detection-readiness generate-profile \
  --events examples/sample_events/azure_ad_signin.jsonl \
  --name my_environment \
  --source azure_ad_signin \
  --index azure_idx \
  --sourcetype azure:aad:signin \
  --output generated_profile.yaml
```

### Generate starter SPL

```bash
detection-readiness generate-spl \
  --profile examples/azure_profile.yaml \
  --family password_spray
```

### AI narrative summary (optional)

```bash
export ANTHROPIC_API_KEY=sk-...
detection-readiness narrate --input outputs/password_spray_azure.json
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

## Example Generated SPL

```
detection-readiness generate-spl --profile examples/endpoint_profile.yaml --family suspicious_process_execution
```

```spl
| tstats count from datamodel=Endpoint.Processes
  where Processes.process_name IN ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe")
  by Processes.dest Processes.user Processes.process_name Processes.parent_process_name _time span=1h
```

## Project Structure

```
src/detection_readiness/
  schemas/        # Pydantic models (environment, family, result)
  loaders/        # YAML/JSON file loading and validation
  scoring/        # Deterministic scoring engine
  engine/         # Assessment orchestration
  explain/        # Template-based + optional AI explanation generation
  discovery/      # Sample-event-based field discovery
  splunk/         # Splunk REST API client and datamodel health checks
  generators/     # Profile auto-generation and SPL content factory
  cli/            # Typer CLI commands
families/         # Detection family definitions (YAML)
examples/         # Example environment profiles and sample events
outputs/          # Example assessment outputs
tests/            # Unit and smoke tests (90 tests)
```

## Detection Families

| Family | Description |
|---|---|
| `password_spray` | Password spray attacks against authentication systems |
| `impossible_travel` | Geographically impossible authentication patterns |
| `suspicious_process_execution` | Execution of suspicious or malicious processes |
| `email_impersonation` | Email sender spoofing and impersonation |
| `lateral_movement` | Adversary movement between hosts via remote services |
| `data_exfiltration` | Abnormal outbound data transfers |
| `privilege_escalation` | Unauthorized privilege elevation attempts |

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

## Splunk API Integration

The Splunk REST API client enables live environment profiling without manual profile authoring:

```python
from detection_readiness.splunk import SplunkClient, check_datamodel_health
from detection_readiness.generators import generate_profile_from_splunk

client = SplunkClient(base_url="https://splunk:8089", token="your-token")

# Auto-generate a profile from live data
profile = generate_profile_from_splunk(
    client,
    environment_name="production",
    source_configs=[
        {"name": "azure_ad_signin", "index": "azure", "sourcetype": "azure:aad:signin"},
    ],
    check_datamodels=["Authentication", "Endpoint"],
)

# Check datamodel health
health = check_datamodel_health(client, ["Authentication", "Endpoint"])
for dm in health:
    print(f"{dm.name}: healthy={dm.healthy}, events={dm.event_count}")
```

## Running Tests

```bash
pytest tests/ -v
```

90 tests covering profile parsing, family loading, scoring logic, field discovery, SPL generation, profile auto-generation, Splunk client, datamodel health, AI narrator, explanation generation, and CLI smoke tests.

## Current Limitations

- Splunk API integration requires network access to a Splunk instance
- AI narratives require an API key (Anthropic or OpenAI)
- No web UI
- No sample event scanning directly from Splunk (use exported events)

## Roadmap

- [x] Splunk REST API integration for live environment profiling
- [x] Sample-event-based field discovery
- [x] Datamodel health checks
- [x] Environment profile auto-generation
- [x] Content factory integration (generate SPL from readiness results)
- [x] AI-generated narrative summaries (optional)
- [x] Additional detection families (lateral movement, data exfiltration, privilege escalation)
- [ ] Batch assessment across multiple families
- [ ] Profile diffing (compare two environments)
- [ ] MITRE ATT&CK mapping for detection families
- [ ] Splunk-side sample event export helper
- [ ] Interactive profile builder wizard
- [ ] CI/CD integration (readiness gates for detection pipelines)

## License

MIT
