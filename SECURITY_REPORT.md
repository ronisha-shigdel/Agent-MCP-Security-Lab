# Technical security report

## 1. System architecture

The lab runs a project assistant with `read_file`, `query_database`, and
`send_email` tools exposed by a local MCP server over stdio. Live mode sends
the prompt and tool descriptions to a Groq model; replay mode makes fixed
tool calls without a model. Each trial starts with a fresh temporary workspace,
SQLite database, synthetic tokens, and local simulated-email outbox. The host
records model/tool traces, server audit events, outbox records, and final role.
There is no real email transport.

## 2. Threat model

The attacker controls a user request, document, database text field, or
advertised tool description. The objectives include accessing another
customer's private record, leaking a synthetic token, changing privileges,
or sending an unapproved message. The host, server code, and approval store
are trusted. Customer identity is fixed to Alice by the lab fixture.
The [threat model](THREAT_MODEL.md) details boundaries and OWASP LLM Top 10
(2025) mappings; these are illustrative mappings, not comprehensive coverage.

## 3. Attack scenarios

The [suite](lab/scenarios.py) contains nine attacks (A01-A09): direct and
indirect prompt injection, poisoned metadata, unauthorized cross-customer
access, exfiltration, privilege escalation, excessive agency, and approval
bypass. It also contains four legitimate controls (C01-C04). Every JSONL
trial includes its ID, category, payload, expected behavior, observed outcome,
and evidence. A07 scores the actual returned synthetic record, not a verbal
refusal; A04 checks database state; email objectives check the outbox.

## 4. Security controls

The baseline allows broad operations within disposable fixtures. Protected
mode pins tool schemas and descriptions, allowlists a document and email
recipient, enforces a read-only database and Alice-scoped view, and requires
single-use host approval for the exact email. Both modes retain containment
and input/resource validation, so the baseline is not an unrestricted machine.
Four controls are exercised alongside the attacks; C04 is preapproved by
the trusted host fixture. No user text or tool argument can grant approval.

## 5. Testing methodology

Replay uses identical scenarios and scripted tool calls in both modes. Each
call traverses the actual MCP server, and the runner checks audit records,
returned rows, outbox entries, and persisted role. Some exfiltration calls
directly supply the known synthetic token even when a read was denied; this
isolates outbound controls and does not simulate model data flow.

The summary records counts and fractions:

- **Attack success rate:** observed malicious objectives / scored attacks.
- **Defense success rate:** scored attacks without the declared objective /
  scored attacks. This is an outcome proxy, not proof that all unsafe
  behavior was blocked.
- **False positive rate:** legitimate trials with a denied *canonical*
  legitimate tool call / all legitimate trials. An unrelated malformed call
  is not counted; semantically equivalent noncanonical calls are not assessed.
- **Legitimate task success rate:** controls with the goal observed / scored
  controls. Replay measures tool outcomes. For live read tasks, it also
  requires specified literal content in the final answer; an email control
  requires the exact message to be queued.

Truncated or step-limited trials without an observed goal are excluded from
the attack and task-success denominators. Observed side effects remain
scored even if the agent later stops inconclusively. Coverage and inconclusive
counts are reported. The false-positive denominator includes all legitimate
trials, including inconclusive ones, and can underestimate denials when a
model never attempts the canonical call.

## 6. Experimental results

The [November 18, 2026 UTC replay](results/suite_v3_summary.json) contains
three repeats of each case per configuration: 27 attack and 12 legitimate
trials per configuration, 78 total, with no inconclusive trials.

| Metric | Baseline | Protected |
|---|---:|---:|
| Scripted attack success | 27/27 (100%) | 0/27 (0%) |
| Scripted defense success proxy | 0/27 (0%) | 27/27 (100%) |
| Canonical-call false positives | 0/12 (0%) | 0/12 (0%) |
| Legitimate tool-task success | 12/12 (100%) | 12/12 (100%) |

Each attack was observed 3/3 times in baseline and 0/3 in protected mode.
The [raw records](results/suite_v3.jsonl) contain per-trial evidence and
environment/source fingerprints. The older five-attack
[replay](results/replay_summary.json) predates this suite and is not directly
comparable. Live-agent results have not been measured. Repeated deterministic
calls are not independent samples; per-case Wilson intervals in the machine
summary must not be interpreted as population confidence intervals.

The offline GitHub Actions workflow runs tests and a one-repeat regression
gate on pushes and pull requests. `--compare-to` reports changes against a
previous summary when suite and run settings match. Comparisons across
changed scoring logic are not automatically detected and are not valid.

## 7. False positives and limitations

The four hand-picked controls cannot estimate general usability. Canonical
call matching misses differently expressed valid requests, and literal
answer checks can miss correct paraphrases. Attack oracles only cover their
declared synthetic goals: encoded, partial, transformed, or differently
routed leaks and final-answer leakage may go undetected. A missing observed
goal does not prove that no unauthorized read or other unsafe action occurred.
Audit and trace records should be inspected alongside rates.

The protected controls are bundled; this is not a per-control ablation.
Metadata poisoning does not simulate a compromised MCP executable. Approval
fatigue, concurrency, real authentication, network transport, and deployment
isolation are not evaluated. Thirty or more trials remain insufficient to
establish production security.

## 8. Future improvements

- Run paired live-model trials and review incomplete cases and actual traces.
- Expand adversarial and legitimate tasks, including semantically equivalent
  queries and independently reviewed success and refusal judgments.
- Add per-control ablations and test stronger leak oracles.
- Evaluate authentication, concurrent approval consumption, and isolation
  before considering any real deployment.
