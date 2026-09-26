package com.polygraphene.df.reroot;

/**
 * A bounded, one-shot handoff of a value produced by another thread.
 *
 * Used for the `CONTROLLER` binder that `network_stack` sends back across the
 * hop: the run thread waits for it with a deadline, and the broadcast receiver
 * hands it over from a different thread. That is the "controller timeout before
 * native start" case the Auto Root plan requires a negative test for — a timeout
 * here means the run refuses before anything destructive happens, so it has to be
 * a real deadline and not an indefinite wait.
 *
 * It is a pure class with no Android imports for the reason AGENTS.md section 5
 * gives: on a device the timeout is 30 seconds and cannot be provoked on demand,
 * while here it is a few milliseconds and every branch is reachable — value
 * arrives early, value arrives late, value never arrives, and the waiter is
 * interrupted.
 *
 * @param <T> whatever is being handed over; the class never inspects it.
 */
public final class AwaitBox<T> {

    /** Told how much of the deadline is left, once per wait slice. */
    public interface Progress {
        void waiting(long msLeft);
    }

    private final Object lock = new Object();
    private T value;

    /** Hand the value over and wake every waiter. A null value is ignored. */
    public void set(T v) {
        if (v == null) return;
        synchronized (lock) {
            value = v;
            lock.notifyAll();
        }
    }

    /** Whatever has been handed over so far, or null. */
    public T peek() {
        synchronized (lock) {
            return value;
        }
    }

    /** Forget any handed-over value, so one instance can serve several runs. */
    public void clear() {
        synchronized (lock) {
            value = null;
        }
    }

    /**
     * Wait up to [timeoutMs] for a value.
     *
     * @param sliceMs  how long a single wait lasts before [progress] is told how
     *                 much is left; the loop exists so a long deadline still
     *                 reports something to the operator's log.
     * @return the value, or null on timeout or interruption. Null is never
     *         "maybe": every caller treats it as a refusal.
     */
    public T await(long timeoutMs, long sliceMs, Progress progress) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (lock) {
            while (value == null) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) return null;
                if (progress != null) progress.waiting(left);
                try {
                    lock.wait(Math.min(left, Math.max(1, sliceMs)));
                } catch (InterruptedException e) {
                    // Preserve the flag: the caller decides what an interrupted
                    // run means, and swallowing it would hide a cancellation.
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
            return value;
        }
    }
}
