package com.polygraphene.df.reroot;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Run work with a deadline the CALLER is guaranteed to observe.
 *
 * <h2>Why this exists</h2>
 *
 * A synchronous Binder transaction has no timeout. {@code binder.transact(code,
 * data, reply, 0)} returns when the remote replies, and if the remote's handler
 * wedges it never returns. The companion bounds its own {@code su} child, and
 * bounding a child is not bounding the call: the handler also resolves
 * packages, hashes certificates and occupies a binder thread, and none of that
 * is covered by the child's deadline.
 *
 * So the client ran a call it described as bounded and was not. Found in the
 * owner's review of PR C, with the constant that proved it: a declared
 * {@code ATTEST_TIMEOUT_MS} that nothing read.
 *
 * <h2>What is bounded, and what is not — read this before trusting it</h2>
 *
 * The CALLER is bounded: it returns at the deadline, every time. The WORK is
 * not cancelled, because a synchronous binder transaction cannot be - there is
 * no interruptible wait to interrupt, the thread is parked in the kernel driver
 * until the remote answers or dies.
 *
 * So a timeout here leaks one daemon thread, blocked until the remote replies
 * or the system reclaims it (which unbinding makes likely). That is the
 * trade-off, stated rather than hidden: one parked daemon thread per timed-out
 * attempt, against a caller stalled forever inside {@code system_server}. The
 * attempts are operator-driven and the thread is a daemon, so it holds nothing
 * open; an automatic caller that could retry in a loop would make this the
 * wrong trade and must not be given one.
 *
 * Pure Java on purpose: the hung case is the whole point and cannot be produced
 * on a device on demand, so it is exercised in {@code BoundedCallTest}.
 */
public final class BoundedCall {

    private BoundedCall() {}

    public interface Work<T> {
        T run() throws Exception;
    }

    public static final class Result<T> {
        /**
         * The work's value. {@code null} is a legitimate value, which is why
         * {@link #timedOut} and {@link #failure} exist as separate facts rather
         * than being inferred from it (AGENTS.md §3.7).
         */
        public final T value;
        /** The deadline passed with the work still running. */
        public final boolean timedOut;
        /** The work threw. Distinct from a timeout and from a null value. */
        public final Throwable failure;

        private Result(T value, boolean timedOut, Throwable failure) {
            this.value = value;
            this.timedOut = timedOut;
            this.failure = failure;
        }

        /** The work finished and did not throw. */
        public boolean completed() {
            return !timedOut && failure == null;
        }
    }

    /**
     * @param name      thread name, so a parked leak is identifiable in a dump
     * @param timeoutMs the caller's deadline; {@code <= 0} refuses immediately
     *                  rather than waiting forever, because a non-positive
     *                  deadline is a caller bug and the safe reading of a bug
     *                  is "do not wait"
     */
    public static <T> Result<T> run(String name, long timeoutMs, Work<T> work) {
        if (work == null) {
            return new Result<>(null, false, new IllegalArgumentException("no work"));
        }
        if (timeoutMs <= 0) {
            return new Result<>(null, true, null);
        }
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<T> value = new AtomicReference<>(null);
        final AtomicReference<Throwable> thrown = new AtomicReference<>(null);
        Thread worker = new Thread(() -> {
            try {
                value.set(work.run());
            } catch (Throwable t) {
                thrown.set(t);
            } finally {
                done.countDown();
            }
        }, name);
        /*
         * Daemon, because this thread may outlive the call it was started for
         * and must never be the reason a process stays alive.
         */
        worker.setDaemon(true);
        worker.start();
        boolean finished;
        try {
            finished = done.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            // An interrupted caller is not a completed call.
            return new Result<>(null, true, e);
        }
        if (!finished) {
            return new Result<>(null, true, null);
        }
        Throwable failure = thrown.get();
        if (failure != null) {
            return new Result<>(null, false, failure);
        }
        return new Result<>(value.get(), false, null);
    }
}
