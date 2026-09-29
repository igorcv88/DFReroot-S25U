package com.polygraphene.df.reroot;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Serialises soft-reboot requests until the durable per-boot claim takes over.
 * A refusal before that boundary releases the process-local guard; after a
 * successful durable claim the lease is deliberately never released.
 */
public final class SoftRebootDispatchGuard {
    private final AtomicBoolean held = new AtomicBoolean(false);

    public Lease tryAcquire() {
        return held.compareAndSet(false, true) ? new Lease() : null;
    }

    public final class Lease implements AutoCloseable {
        private boolean durableClaimed;
        private boolean closed;

        private Lease() {}

        public void markDurableClaimed() {
            durableClaimed = true;
        }

        @Override
        public void close() {
            if (!closed && !durableClaimed) {
                held.set(false);
            }
            closed = true;
        }
    }
}
