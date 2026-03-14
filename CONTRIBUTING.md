# Contributing

Thanks for taking the time to contribute. All help is welcome — corrections, new protocols, better detection notes, cleaner remediation steps.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Ways to contribute

- **Bug reports:** Incorrect info, broken links, typos
- **Improvements:** Better risk descriptions, more precise ATT&CK mappings, additional monitoring indicators
- **New protocols:** Missing protocols relevant to defensive operations
- **Style and clarity:** Cleaner phrasing, more actionable wording

---

## Reporting issues

Open a [GitHub Issue](https://github.com/Nervi0zz0/blue-team-ref/issues). Before you do, check if one already exists.

For **bugs**, describe what's wrong, where it is, and what the correct information should be.
For **suggestions**, explain what you'd change and why it improves the reference.

Use labels where relevant: `bug`, `enhancement`, `documentation`, `new-protocol`.

---

## Submitting a pull request

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/blue-team-ref.git`
3. Create a branch with a descriptive name:
   ```bash
   cd blue-team-ref
   git checkout -b fix-smb-attck-link
   ```
4. Make your changes, following the style guide below
5. Commit with a clear message:
   ```bash
   git commit -m "fix: correct ATT&CK link in SMB section"
   # Other examples:
   # feat: add QUIC protocol entry
   # docs: improve HTTP risk description
   ```
6. Push your branch: `git push origin fix-smb-attck-link`
7. Open a pull request against `main`. If it closes an existing issue, include `Closes #NUMBER` in the description.

---

## Style guide

Follow the structure used in existing entries:

```
### [Protocol Name](link-to-spec)
**Port:** `port/proto` | **Use:** brief description | **Sev:** Low/Medium/Critical
**Risk:** [[TACTIC/TECHNIQUE]](ATT&CK link) Description
**Monitor:** Key indicators and anomalies
**Fix:** 1. Step | 2. Step | 3. Step
```

- Use `backticks` for ports, commands, event IDs, file names, and protocol names
- Use **bold** for emphasis on critical points
- Keep entries concise and actionable — no padding
- Verify all links (RFCs, ATT&CK, vendor docs) before submitting
- Severity levels: Low / Medium / Critical

---

For any questions about the process, open an issue.
