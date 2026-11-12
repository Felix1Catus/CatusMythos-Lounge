# P04 — STATE_LIVENESS
**Kills:** U7 (state-blindness)
**Trigger:** before every authed wave, and every ~25 authed requests.

One cheap liveness call. On **401**:
1. **HALT IMMEDIATELY.**
2. Mark every artifact after that point **"post-token-death"**.
3. Re-auth.
4. Resume only with fresh state.

**Never analyse responses received after the first 401.** They are corpses; reading them
manufactures false negatives.

Same discipline for every other piece of mutable state: **egress IP** (log it — a sudden wall of
429/000 is your own burn until proven otherwise), file locks, browser profile dirs, cookie jars.
Verify before assuming.
