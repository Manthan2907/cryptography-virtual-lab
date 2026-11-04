# EXP-FW — Different Types of Firewalls

## Integration status

Prepared locally against `Manthan2907/cryptography-virtual-lab` at `97c5aac`.
The remote has **no `group-firewall-types` branch** and no existing assigned firewall folder. This checkout is detached from HEAD; no commits, pushes or pull requests were made. The integration team must confirm the folder/branch assignment before submission. The proposed folder is `experiments/firewall-types/`, which matches the group's `group-<folder>` validation convention.

Only this proposed experiment folder is added. The original standalone firewall project is unchanged. This is an adaptation of that code, not a replacement implementation.

## Template mapping

| Shared tab | Existing functionality |
| --- | --- |
| Aim & Objectives | Standard shared Aim & Objectives card with firewall-specific aim and three objectives |
| `theory` | Six detailed architectures in the standard shared Theory content card |
| `procedure` | Seven numbered steps in the standard shared Procedure content card |
| `simulation` | Original engine, auto-running presets, three-stage animation, editable rules, logs, two-firewall and six-firewall comparison; architecture table as a subview |
| `quiz` | Five randomized practical scenarios from 24, ten MCQs, explanations, saved progress, combined report |
| References | Existing NIST and OWASP references |
| Feedback | **Official template section and shared dependencies preserved verbatim** |

The college banner, header structure, back link, seven tab buttons, panel IDs, shared stylesheet references and shared JavaScript references are retained. `../../js/common.js` controls the top-level tabs. The adapter only renders content into non-feedback `.fw-lab` hosts. Original engine/data/functions remain; standalone page routing is replaced by a thin shared-tab adapter. There are no global JavaScript declarations: the module is enclosed in an IIFE.

`style.css` follows the existing MD5 module's use of a local stylesheet, but every selector is constrained to `.fw-lab`, all keyframes are prefixed `fw-`, and the palette aliases shared `--color-*` tokens. No shared CSS or outer-layout/navigation selectors are overridden. The group theme is dark coffee/mocha; the standalone cream shell is intentionally replaced by the shared theme. Shared feedback receives no module styling or handlers.

## Feedback preservation

The `feedback` section, Feedback tab button, and shared script includes for `students-roster.js`, `crypto-feedback.js`, and `feedback.js` match `experiments/TEMPLATE.html` byte-for-byte. Shared feedback files, links, forms, encryption, submission behavior, roster and configuration have not been edited. The old standalone local-feedback form is not mounted into this integration. Feedback submission was not performed during testing.

## Setup and dependencies

No package installation or build is required. Keep all four module files together under `experiments/firewall-types/` in the group repository. Run from the repository root:

```sh
python3 -m http.server 8000
```

Open `http://localhost:8000/experiments/firewall-types/`. On GitHub Pages the expected path is `/cryptography-virtual-lab/experiments/firewall-types/`. Shared assets use `../../` paths and local assets use relative paths. Opening the module independently without the group repository will not provide shared assets. The simulation itself sends no traffic and requires no libraries. The shared feedback dependencies remain owned by the integration team.

## Input

Firewall architecture; source/destination IPv4; TCP/UDP/ICMP; destination port; inbound/outbound direction; modeled new/established/invalid state; declared HTTP/HTTPS/DNS/SSH/Other application; HTTP path; explicit threat flags; session-negotiation outcome. Rules accept a priority, allow/deny action, protocol, port, exact IPv4 or wildcard addresses, and direction.

## Output

Allow/block verdict; plain-English reason; ordered inspection steps; send/inspect/outcome visualization; timestamped, filterable traffic log; fixed-packet architecture comparison; practical and quiz scores; missed-topic review; printable completion report. No packet capture or external network enforcement occurs.

## Retained policy semantics

Lowest numerical priority wins; ties use row order. Default deny for unmatched header rules. Default rules deny TCP/22, allow TCP/80 and TCP/443, and allow UDP/53. ICMP only matches wildcard-port rules.

- Packet filtering uses headers only.
- Stateful rejects invalid state and accepts modeled established flows before new-flow rules.
- Circuit gateway requires header approval and valid TCP negotiation.
- HTTP(S) proxy requires header approval, supports TCP web traffic and denies `/admin` paths.
- NGFW applies state/header policy, an HTTP/HTTPS/DNS allowlist and simulated threat signatures, including on established flows.
- WAF independently inspects modeled HTTP(S), decoded path patterns and SQLi/XSS indicators. Non-HTTP passes explicitly outside scope; this is not a safety endorsement.

## Test cases

| Input | Expected result |
| --- | --- |
| Normal browsing, Packet Filtering | Allowed |
| SSH TCP/22, Packet Filtering | Blocked by priority 10 |
| HTTPS malware flag, Packet Filtering versus NGFW | Allowed versus blocked |
| UDP/53, Circuit gateway | Blocked (TCP-only teaching model) |
| `/admin/settings`, Proxy | Blocked |
| Established TCP/8443, Stateful | Allowed |
| New TCP/8443, Stateful | Default deny |
| Invalid state, Stateful or NGFW | Blocked |
| SQLi HTTP request, WAF | Blocked |
| SSH, WAF | Allowed, explicitly outside scope |
| Invalid IPv4 `999.0.0.1` | Input rejected without simulation |
| Priority 1 deny-all | Header-based new traffic blocked |
| Restart practical assessment | Five unique scenarios, none from immediately previous set |
| Complete ten correct quiz answers | 10/10, explanations and completion report |
| Rapid scenario switching / tab change | Old animation canceled; no stale verdict |

## Verification performed

- JavaScript syntax passed.
- Automated checks passed for 24 practical verdicts and 100 non-overlapping consecutive question sets.
- Browser: shared Simulation tab loaded; SSH blocked; normal browsing ran; invalid IPv4 was rejected; reset restored defaults; malware comparison showed Packet Filtering allowed and NGFW blocked.
- Browser: five practical answers were graded and persisted; all ten quiz questions completed with 10/10; combined report showed the completed practical score plus quiz score. Both outcome branches were exercised.
- Browser console checked during testing: no errors or warnings observed.
- Shared feedback markup/dependency preservation, scoped selectors, required IDs, theory word count, relative asset existence and Git scope verified separately.
- Narrow and desktop layouts checked with no horizontal page overflow or duplicate DOM IDs. The original deterministic engine was verified byte-for-byte unchanged.
- No feedback form was submitted. Cross-browser coverage and the OS print dialog remain manual checks.

## Manual review checklist

Visit all seven shared tabs; confirm banner and navigation match other modules. Test each preset under each architecture, add/edit/delete rules, inspect logs and compare results. Reload during a quiz to confirm progress. Complete a new practical set and confirm the report updates. Check print/save report (allow its popup if necessary). Review narrow-screen layout. Open Feedback only to confirm the unchanged shared form; use the team's normal process for end-to-end feedback testing.

## Integration-team actions (not performed)

1. Confirm `firewall-types` assignment and create the matching `group-firewall-types` branch.
2. Add the module to the root portal experiment list/navigation if desired. No portal file was changed here.
3. Add a firewall entry to shared documentation/API catalogs if desired; `docs/API_SPECS.md` currently has no firewall-specific contract.
4. Review the folder-local stylesheet approach, consistent with the MD5 precedent, before merging.
5. Run the team's PR workflow from the assigned branch after user approval to push/open a PR.

## Limitations

Educational deterministic simulation only: no actual traffic, TLS decryption, real connection table, protocol parsing, CIDR/IPv6 or production threat engine. Applications/threats/state are supplied lab inputs. HTTPS assumes decrypted content. Architectures overlap in real products. Local state uses `group-exp-fw-*` keys so it does not overwrite standalone-lab progress; rules/logs remain session-only. Each new practical visit generates a fresh set; the report uses the latest completed practical result. Feedback availability and server configuration are inherited unchanged from the group project. New shared-tab navigation returns to module views without replacing the shared controller.

## Exact-template presentation revision

Aim, Theory, Procedure and References now use the same `content-placeholder` markup and shared styling as `properties-hash-functions`. The standalone hero, statistics cards, learning-path bar and custom theory cards are no longer rendered. Local styles apply only inside Simulation and Assessment / Quiz. Header, banner, tab navigation and feedback remain untouched. Functionality is retained within the relevant experiment tabs. Structural checks passed for the revised standard panels; the earlier browser tests cover the unchanged simulator/quiz engine.
