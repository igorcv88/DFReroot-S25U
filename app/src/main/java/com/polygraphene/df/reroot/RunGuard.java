package com.polygraphene.df.reroot;

import java.util.concurrent.atomic.AtomicReference;

/**
 * The single owner of a DirtyFrag run, for the whole process.
 *
 * There are two entry points now - the operator's button and the boot service -
 * and exactly one of them may reach the destructive transaction. This lives in
 * its own pure class, rather than as an `AtomicReference` inside
 * {@link DfrRootCoordinator}, because "two callers race and exactly one wins" is
 * a decision, and AGENTS.md section 5 puts decisions where a host test can drive
 * them. The race is one of the negative cases the Auto Root plan requires, and it
 * cannot be produced on demand on a device.
 *
 * Deliberately not reentrant: the same caller asking twice is the "already
 * running" case, not a nested run.
 */
public final class RunGuard {

    private final AtomicReference<String> owner = new AtomicReference<>(null);

    /**
     * Take the run.
     *
     * @return null when [who] now owns it, or the name of the caller that holds
     *         it. Returning the holder rather than a bare boolean is what lets
     *         the loser say who is running instead of just refusing.
     */
    public String tryAcquire(String who) {
        if (who == null || who.trim().isEmpty()) {
            // An unnamed owner cannot be reported to the loser, and a guard whose
            // refusals cannot be explained is the kind nobody trusts.
            return "invalid";
        }
        if (owner.compareAndSet(null, who)) return null;
        String held = owner.get();
        // The holder can release between the CAS and this read; that means the
        // run ended, and the caller may try again rather than being told a name
        // that is no longer true.
        return held == null ? "released" : held;
    }

    /** Give the run back. Idempotent, so a `finally` can always call it. */
    public void release() {
        owner.set(null);
    }

    /** Who holds the run, or null. */
    public String currentOwner() {
        return owner.get();
    }
}
