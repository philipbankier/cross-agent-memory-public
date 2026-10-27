# Documentation

Start with a small working session. Remote storage, continuous capture and backfill are additions,
not prerequisites for seeing the product.

| I want to... | Read this |
| ------------ | --------- |
| Understand the project or run the synthetic demo | [README](../README.md) |
| Connect my first assistant and source | [First session](getting-started.md) |
| See exact setup commands and recovery behavior | [Agent-guided setup](deployment/agent-guided-setup.md) |
| Run the node on another computer or use B2 | [Remote operation](../REMOTE.md) |
| Use Linux containers | [Container profile](deployment/container-profile.md) |
| Capture eligible browser conversations | [Chrome capture](../browser/capture/README.md) |
| Keep native history current | [Collector pairing](deployment/native-collector-pairing.md), [service setup](deployment/native-collector-service.md) |
| Understand how answers use evidence | [Query skill](../skills/cross-agent-memory/SKILL.md) |
| Diagnose an installation or update it | [Runtime and operational notes](deployment/runtime-notes.md) |
| Verify a downloaded release | [Artifact verification](deployment/verify-release.md) |
| Build or contribute | [Contributing](../CONTRIBUTING.md), [agent instructions](../AGENTS.md) |
| Review trust and data handling | [Security](../SECURITY.md), [memory contract](architecture/memory-contract.md) |

## Engineering References

[Evidence ledger](architecture/0001-canonical-evidence-ledger.md) explains why source evidence and
derived memory are different. [Architecture contracts](architecture/) define behavior; they are not
an additional first-run checklist. [Release status](release-readiness.md) separates tested source
from published artifacts. [FAQ](faq.md) covers common expectations and boundaries.
