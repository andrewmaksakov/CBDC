# Changes for Andrew's review — positioning pass, 21 Jul 2026

**What this pass is:** the 21 Jul contribution review found the paper's §2.4 gap claim
("limited analysis of CBDC architectures that achieve security through mechanism design
rather than surveillance") factually false — there is a 30-year cryptographic-compliance
lineage (trustee e-cash → compact e-cash → GGM16 → Platypus/PEReDi CCS 2022 → Privacy
Pools) plus live BIS programs (Aurora, Hertha) doing privacy-preserving AML at scale.
This pass fixes the frame: cites the lineage, repositions the novelty to what survives
(abandonment mechanism, identity-axis decomposition, policy-bridge synthesis), adds two
honest-limitation treatments (adversarial probing oracle; FATF tipping-off conflict),
and strips the "game-theoretic" label from a section with no formal game theory.

**NOT touched (blocked on Murad's pending §4.5 rewrite):** all §4.5 numbers, the
abstract's 87–95% / "zero marginal" headline, §6.5's 5–13% figures, §8.3's first
paragraph repeating the headline numbers, and everything in §5.4 (your stack + sim).

**Files changed:** `main.tex`, `references.bib` (8 entries appended, all live-verified
21 Jul), `repo-fix-bundle/references.bib` + `repo-fix-bundle/FORWARD_NOTE.md` +
`cbdc-repo-fix-bundle-21jul2026.zip` (re-synced). Recompiled clean: 37pp, 0 errors,
0 undefined citations.

## New references (all verified against live records this session)

| Key | Work | Verified via |
|-----|------|--------------|
| `CamenischMaurerStadler1996` | Camenisch, Maurer & Stadler, "Digital Payment Systems with Passive Anonymity-Revoking Trustees," ESORICS 96, Springer, pp. 33–43 | doi.org/10.1007/3-540-61770-1_26 (Springer) |
| `Camenisch2005CompactEcash` | Camenisch, Hohenberger & Lysyanskaya, "Compact E-Cash," EUROCRYPT 2005, Springer, pp. 302–321 | eprint.iacr.org/2005/060 + Crossref 10.1007/11426639_18 |
| `Garman2016Accountable` | Garman, Green & Miers, "Accountable Privacy for Decentralized Anonymous Payments," FC 2016, Springer, pp. 81–98 | eprint.iacr.org/2016/061 + Crossref 10.1007/978-3-662-54970-4_5 |
| `Wuest2022Platypus` | Wüst, Kostiainen, Delius & Capkun, "Platypus: A CBDC with Unlinkable Transactions and Privacy-Preserving Regulation," ACM CCS '22, pp. 2947–2960 | Crossref 10.1145/3548606.3560617 |
| `Kiayias2022PEReDi` | Kiayias, Kohlweiss & Sarencheh, "PEReDi: Privacy-Enhanced, Regulated and Distributed CBDCs," ACM CCS '22, pp. 1739–1752 | Crossref 10.1145/3548606.3560707 + eprint.iacr.org/2022/974 |
| `Buterin2024PrivacyPools` | Buterin, Illum, Nadler, Schär & Soleimani, "Blockchain Privacy and Regulatory Compliance: Towards a Practical Equilibrium," Blockchain: Research and Applications 5(1):100176, 2024 | Crossref 10.1016/j.bcra.2023.100176 |
| `BISAurora2023` | BIS Innovation Hub, "Project Aurora: The Power of Data, Technology and Collaboration to Combat Money Laundering across Institutions and Borders," May 2023 | bis.org/publ/othp66.htm + bis.org topic page |
| `BISHertha2025` | BIS Innovation Hub & Bank of England, "Project Hertha: Identifying Financial Crime Patterns in Real-Time Retail Payment Systems," June 2025 | bis.org/publ/othp96.htm (1.8M accounts / 308M txns; +12% illicit accounts, +26% novel patterns) |

FATF R.21 (tipping-off) and UK POCA s.333A wording verified against cfatf-gafic.org
and legislation.gov.uk respectively; cited via the existing `FATF2012` entry.

## Prose changes, before → after

1. **Abstract, para 2:** "This creates a game-theoretic deterrent: illicit actors cannot
   complete transactions…" → "This creates a strategic deterrent: illicit actors cannot
   complete flagged transactions…" (§4 contains no formal game theory; label was
   indefensible. "Flagged" added for accuracy.)

2. **Research Context:** "architectural enforcement of privacy that achieves superior
   crime detection" → "…that pursues crime detection…" ("superior" is asserted nowhere
   in the evidence.)

3. **Research Context:** "The contribution lies in demonstrating that… Privacy-preserving
   architecture can achieve equivalent or superior crime detection by creating
   game-theoretic incentives that make illicit transactions structurally impossible to
   complete" → "The contribution lies in arguing that… can approach the crime detection
   of surveillance-based designs by creating strategic incentives that prevent flagged
   transactions from completing."

4. **§1.3:** "Its core innovations include:" → "Its core mechanisms include:" (three of
   the four are prior art as mechanisms; the four-count enumeration itself is unchanged).

5. **§1.4:** "Section 4 analyzes game-theoretic properties… and demonstrates why it
   creates effective deterrence" → "Section 4 presents a strategic analysis… and argues
   that it can deter illicit use."

6. **§2.1 (goodell paragraph):** "receives minimal attention" → "receives minimal
   attention in official design documents, even though the cryptographic literature
   reviewed in Section 2.2 has developed exactly such systems." (Scopes the claim so it
   no longer contradicts the newly cited lineage.)

7. **§2.2:** REPLACED the paragraph "However, this literature predominantly accepts the
   surveillance–privacy trade-off framing…" with TWO new paragraphs: (a) the
   cryptographic-compliance lineage (CMS 1996 trustee e-cash, Compact E-Cash, GGM16,
   Platypus, PEReDi, Privacy Pools); (b) an honest statement of what that lineage leaves
   open — nobody quantifies what identity access buys detection, nobody specifies the
   flag-to-outcome transaction lifecycle. The old paragraph's claim was false for the
   uncited half of the literature.

8. **§2.3 (new paragraph before the FATF 2024 paragraph):** Aurora + Hertha described,
   with the paper's strongest card stated: both programs ablate the DATA-SHARING axis
   (what more cross-institution visibility buys); neither ablates the IDENTITY axis
   (what knowing who is behind a wallet buys beyond pseudonymous linking). "That is the
   experiment this paper runs."

9. **§2.4 (the falsified gap claim):** "The existing literature contains a significant
   gap: limited analysis of CBDC architectures that achieve security through mechanism
   design rather than surveillance." → REPLACED with a precise three-part residual gap:
   (i) identity-axis decomposition unmeasured anywhere, (ii) intervention/abandonment
   lifecycle unspecified in all prior systems, (iii) crypto and policy conversations
   disjoint. Novelty repositioned to: decomposition experiment + abandonment primitive +
   policy-bridge synthesis.

10. **§3.3 Anonymous Notification:** added pointer sentence flagging the tipping-off
    conflict (cross-ref to new §6.6).

11. **§4 heading:** "Game-Theoretic Analysis" → "Strategic Analysis".

12. **§4.2:** "Understanding its game-theoretic structure clarifies why… can achieve
    security outcomes equivalent or superior to surveillance" → "…its strategic
    structure clarifies how… can approach the security outcomes of surveillance-based
    designs," + NEW sentence stating the analysis is informal (no equilibrium results)
    and pointing to the §8.3 repeated-interaction limitation.

13. **§4.4:** bullet heading "Superior detection of sophisticated laundering." →
    "Potential reach into sophisticated laundering." (body already hedged with
    "potentially"; the heading claimed what was never simulated).

14. **§6.1 (new closing paragraph):** abandonment doubles as a free probe of the
    detection boundary; cross-ref to §8.3.

15. **§6.6 (NEW subsection, "Notifying Flagged Parties Is Prohibited Tipping-Off"):**
    states that anonymous notification does what FATF R.21 / POCA s.333A prohibit, that
    the architecture presupposes a prevention-substitutes-for-reporting regime requiring
    FATF amendment, that notification interacts with the probing oracle, and that this
    is an unresolved compliance-design tension, not a solved feature.

16. **§8.1:** "can achieve equivalent or superior crime prevention" → "can achieve
    comparable crime prevention"; "contributes four innovations" → "contributes four
    design mechanisms"; "These four innovations are underpinned…" → "These four
    mechanisms are underpinned…" + NEW honest-novelty sentence: first three mechanisms
    assemble established primitives; the abandonment mechanism and the §4.5
    identity-axis decomposition are, to our knowledge, new.

17. **§8.3 (new fourth limitation paragraph):** costless abandonment as an adversarial
    probing oracle — repeated interaction maps the detection boundary for free; §4's
    deterrence argument is single-round; candidate defenses (randomized thresholds,
    abandonment rate limits, escalating friction) each reintroduce account-level
    consequence; repeated-game modeling named as the paper's most important open
    problem. `\label{sec:limitations}` added to the subsection.

## Why this helps rather than hurts

The old frame was one paragraph away from demolition by any referee who knows GGM16 or
Hertha. The new frame concedes what is prior art, keeps the four-mechanism enumeration
intact, and stakes the paper on the two claims nobody else has made: the identity-axis
ablation and the abandonment primitive. Your §5.4 stack is untouched and now sits inside
a lineage section that makes it look like deliberate engineering on top of known
primitives — which it is.

If you want any of the 17 items reverted or rephrased, say so before the MDPI reformat.

## Verification-pass correction (21 Jul, second agent)

18. **§2.2 Platypus sentence + bib note:** "holding and turnover limits" → "holding and
    receiving limits". The independent verification pass pulled the actual Platypus PDF:
    the word "turnover" never appears in it; the paper's two worked regulation examples
    are holding limits and a receiving limit per time interval (epoch), both enforced via
    zero-knowledge proofs. All other characterizations of the 8 new references were
    re-verified against live records (Crossref, IACR ePrint, Platypus full text via
    Wayback, GGM16 policy list, bis.org Aurora/Hertha pages, legislation.gov.uk POCA
    s.333A) and held up exactly.
