# Scan Health UI Specification

## Purpose

The Scan Health component communicates which security checks were run, the result of each check, and where the user should focus. It must show scan coverage honestly without implying that every possible vulnerability was tested.

## Target-dependent checks

The scanner has one global catalog of possible checks, but each target runs only the checks appropriate for that target.

| Target | Expected applicable checks |
|---|---:|
| OWASP Juice Shop | About 9 with test credentials; fewer without credentials |
| DVWA | About 9 |
| Normal user website | About 6 to 10 safe generic checks |
| Source-code scan | Static-analysis checks |

The UI must use the returned check list to calculate its counts. It must not assume that every scan has the same number of checks.

Recommended header wording:

> Scan health    7 of 9 applicable checks completed - 2 skipped

Use "applicable checks" and "completed" or "checks run" instead of implying that skipped checks were passed.

## Segmented checklist bar

The bar contains one segment for each logical check. A logical check may make several HTTP requests or try multiple payloads internally, but it appears as one segment in the UI.

Each segment has:

- A stable check ID
- A category
- A result state
- An optional finding ID
- A reason when skipped or not applicable

Checks remain in a stable category order between scans. Suggested category order:

1. Authentication and access control
2. Injection and input handling
3. Browser safety
4. Error handling
5. Configuration and transport

### Fixed segment dimensions

Segments keep a fixed size for visual consistency. They should wrap into additional rows instead of shrinking until they become difficult to understand.

Suggested starting dimensions:

- Width: 32px
- Height: 18px
- Gap: 6px
- Border radius: 4px

Desktop and mobile can use the same dimensions. On smaller screens, the bar grows vertically as segments wrap.

## Result states and colors

| State | Visual treatment | Meaning |
|---|---|---|
| Passed | Green | The check ran and found no issue |
| Low | Blue or teal | A low-severity finding was detected |
| Medium | Yellow or amber | A medium-severity finding was detected |
| High | Orange | A high-severity finding was detected |
| Critical | Red | A critical-severity finding was detected |
| Not applicable | Solid gray | The check does not apply to this target |
| Skipped | Gray with diagonal hatch | The check could not run, usually because credentials or setup were missing |

Color must not be the only signal. The legend, tooltip text, accessible labels, and finding sections must state the result in words.

## Interaction

- Passed segments are not clickable.
- Low, medium, high, and critical segments are clickable and jump to their finding detail below.
- Not applicable segments are not clickable.
- Skipped segments may open the reason or the setup instructions, but must not be treated as passed.
- Hovering or focusing any segment shows the check name and result.
- Keyboard users must be able to focus interactive segments.
- Each segment must have an accessible label, for example: "Cross-account basket access: critical finding."

## Expanded sections below the bar

### Passed checks

All passed checks are grouped into one expandable section:

> Passed checks - 14
>
> These checks found no issue.

When expanded, show compact rows rather than large finding cards. Each row should include the check name and a short result.

### Findings

Every low, medium, high, or critical segment maps to its own minimal finding section. A finding section should contain:

- Check name
- Severity badge
- Plain-language result
- Evidence
- Recommended action
- Technical location and confidence where available

### Not applicable and skipped checks

Group these separately from findings:

- Not applicable checks - explain why they do not apply when useful
- Skipped checks - show the missing credentials, permission, or setup reason

These states must not inflate the risk score.

## Risk score and overall status

Keep the risk score, but make it secondary to the plain-language status.

Recommended display:

> Critical issues found
>
> Risk score: 28.2

The risk score is an accumulated comparison value, not a percentage and not a score out of 100. It is calculated from the individual findings:

`finding score = severity points x confidence`

Current severity points:

| Severity | Base points |
|---|---:|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 2 |
| Info | 1 |

The overall status should be based on the highest-severity finding:

- No issues found
- Minor issues found
- Moderate issues found
- Serious issues found
- Critical issues found

Avoid adding a separate overall health score for now. Having both a health score where higher is better and a risk score where higher is worse would create competing interpretations.

## Legend

Place a text legend below the bar. Each entry contains a swatch, state label, and count:

- Passed: 14
- Low: 0
- Medium: 1
- High: 0
- Critical: 2
- Not applicable: 5
- Skipped: 2

The legend is both a summary and a text fallback for users who cannot distinguish the colors.

## Example

```text
Scan health                                      7 of 9 applicable checks completed
Critical issues found                            Risk score: 28.2

[green][red][amber][green][gray][gray-hatch][green][critical][green]

Passed 5   Low 0   Medium 1   High 0   Critical 2   N/A 1   Skipped 1

[+] Passed checks - 5

[!] Cross-account basket access - Critical
    One account can view another account's private information.
    Evidence and recommended action...

[!] CORS configuration - Medium
    The site accepts requests from any website.
    Evidence and recommended action...
```

## Data contract for a check

A future scan response should expose check results separately from findings so that passed and skipped checks can be represented consistently.

```json
{
  "id": "cross_account_basket",
  "category": "access_control",
  "status": "critical",
  "finding_id": "cddaf68cb843",
  "reason": null
}
```

Example passed check:

```json
{
  "id": "authenticated_user_area",
  "category": "access_control",
  "status": "passed",
  "finding_id": null,
  "reason": null
}
```

Example skipped check:

```json
{
  "id": "cross_account_basket",
  "category": "access_control",
  "status": "skipped",
  "finding_id": null,
  "reason": "Two authorized test accounts were not provided."
}
```

## Design decision summary

- Use one combined segmented bar.
- Keep segment dimensions fixed and allow wrapping.
- Group passed checks into one expandable section.
- Give each problem its own compact detail section.
- Keep not applicable and skipped checks visibly separate.
- Show a plain-language overall status before the technical risk score.
- Use one global check catalog with target-specific applicable subsets.
- Count logical checks, not individual requests or payloads.
