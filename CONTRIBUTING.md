# Contributing

Contributions are welcome: new protocols, corrected ATT&CK mappings, additional Event IDs, better detection signatures, and broken link fixes.

---

## Ways to contribute

- **New protocol entry:** Open an [issue](https://github.com/Nervi0z/blue-team-ref/issues/new?template=add-protocol.md) first — describe the protocol, its abuse cases, and why it belongs here
- **Correction:** Wrong Event ID, incorrect ATT&CK reference, broken link, outdated port — submit a pull request directly
- **Better detection logic:** Improved Wireshark filter, more precise Event ID correlation, additional ATT&CK sub-technique mapping
- **Typos and formatting:** Small fixes as pull requests without an issue

---

## Submitting a pull request

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/blue-team-ref.git
   ```
3. Create a descriptive branch:
   ```bash
   git checkout -b add-winrm-protocol
   git checkout -b fix-kerberos-event-id-mapping
   ```
4. Edit `README.md`
5. Commit with [Conventional Commits](https://www.conventionalcommits.org/) prefixes:
   ```bash
   git commit -m "feat: add WinRM to remote access section"
   git commit -m "fix: correct T1558 sub-technique for Kerberoasting"
   git commit -m "docs: add Event ID 4104 to PowerShell section"
   ```
6. Push and open a pull request against `main`. Reference any related issue with `Closes #NUMBER`

---

## Protocol entry format

Follow this structure exactly for new protocol entries:

```markdown
### [Protocol Name](link-to-rfc-or-official-docs)
**Port:** `port/protocol` | **Use:** Legitimate purpose | **Sev:** Low/Medium/Critical
**Risk:** [[TACTIC]](link) Description `[TECHNIQUE_ID]`
**Monitor:** Key detection indicators.
**Fix:** 1. Action | 2. Action | 3. Action.
```

Quality criteria:

- ATT&CK references must link to the correct tactic or technique page
- Event IDs must be verified against the relevant Windows version
- Detection indicators must be specific and actionable — no generic advice
- Wireshark filters must be tested and use display filter syntax
- No emojis, no marketing language, no generic filler
