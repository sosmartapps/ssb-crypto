# Security policy and bug bounty

So Smart Beneficiary protects information people want to survive them, so we want flaws found before real data goes in. **This code is not independently audited.** A reward is offered for real findings.

## How to report
Email **leon@sosmartapps.app** with the subject "SSB security report". Please do not open a public issue for a vulnerability. Include what is wrong, the file and line, and a failing test, script or clear step-by-step proof. We acknowledge within 5 business days.

## Reward
- **$100 (USD) per valid, previously unreported vulnerability** in scope.
- One reward per root cause. If several reports share a cause, the first complete report gets it.
- **Program cap: 5 rewards ($500 total)** until we announce more funding. Reports after the cap are still welcome and credited, but unpaid.
- We decide validity, and we pay by a method we agree with you by email. Rewards are discretionary; this page is not a contract. We may change or end the program, but a report already received is judged under the terms in force when we received it.

## In scope
Code in this repository: `packages/ssb_crypto` and our patches in `third_party/mlkem_native` and `third_party/mldsa_native`. A valid finding breaks a security property the design claims, for example:
- decrypting or forging data without the right keys; accepting tampered, truncated, reordered or replayed data
- learning a Shamir share's secret from fewer than the threshold of shares
- bypassing the key-substitution defense or the two-key release
- confusing two different signed or derived inputs for one (domain-separation flaws)
- memory-safety bugs in our patched native wrappers
- predictable randomness or key material

## Out of scope (no reward)
- Bugs already listed in the repository, or already public, including bugs in upstream libraries that are public
- Issues needing a compromised device, a malicious OS, or physical access to an unlocked device
- Denial of service by very large inputs, rate limits, and theoretical weaknesses with no working proof
- Social engineering, phishing, or attacks on people
- Third-party services (Firebase, Cloudflare, Apple, Google) and our production servers or apps. **Do not test against them or anyone's real data.**
- UI, typos, outdated dependencies with no exploit, and missing best-practice headers

## Safe harbor
Research done in good faith on your own copy of this code, following these rules, is welcome. We will not pursue legal action for it.

## Disclosure
Please keep details private for 90 days or until we ship a fix, whichever is first. With your permission we list you in a "Thanks" section of the fix notes.
