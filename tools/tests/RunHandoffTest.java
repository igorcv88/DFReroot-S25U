import com.polygraphene.df.reroot.AwaitBox;
import com.polygraphene.df.reroot.RunGuard;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Host suite for the two run-control decisions the Auto Root plan requires
 * negative cases for and that no device can be asked to reproduce on demand:
 *
 *   - the Activity and the boot service racing, with exactly one winner;
 *   - the CONTROLLER binder never arriving before the deadline.
 *
 * On hardware the first needs two triggers in the same millisecond and the second
 * needs a 30-second wait with a broken hop. Here both are a few milliseconds.
 */
public class RunHandoffTest {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(boolean ok, String what) {
        if (ok) {
            pass++;
            System.out.println("  ok   - " + what);
        } else {
            fail++;
            System.out.println("  FAIL - " + what);
        }
    }

    // ---- RunGuard -------------------------------------------------------
    private static void guardCases() throws Exception {
        RunGuard g = new RunGuard();
        check(g.currentOwner() == null, "a fresh guard is unowned");
        check(g.tryAcquire("ui") == null, "the first caller takes the run");
        check("ui".equals(g.currentOwner()), "the guard names its owner");
        check("ui".equals(g.tryAcquire("autoroot")),
                "the second caller is refused and told who holds the run");
        check("ui".equals(g.tryAcquire("ui")),
                "the same caller asking twice is 'already running', not a nested run");
        g.release();
        check(g.currentOwner() == null, "release gives the run back");
        check(g.tryAcquire("autoroot") == null, "a released run can be taken again");
        g.release();
        g.release();
        check(g.currentOwner() == null, "release is idempotent, so finally can always call it");
        check("invalid".equals(g.tryAcquire(null)) && g.currentOwner() == null,
                "an unnamed owner is refused rather than taking the run");
        check("invalid".equals(g.tryAcquire("   ")), "a blank owner name is refused");

        // The real race: many threads, one run. Anything but exactly one winner
        // would mean two callers can reach transaction 5 in the same boot.
        final RunGuard r = new RunGuard();
        final int threads = 32;
        final CountDownLatch go = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        final AtomicInteger winners = new AtomicInteger(0);
        final List<String> refusals = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final String who = (i % 2 == 0) ? "ui" + i : "autoroot" + i;
            new Thread(() -> {
                try {
                    go.await();
                    String held = r.tryAcquire(who);
                    if (held == null) {
                        winners.incrementAndGet();
                    } else {
                        synchronized (refusals) {
                            refusals.add(held);
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        go.countDown();
        done.await();
        check(winners.get() == 1, "32 racing callers produce exactly one owner (got "
                + winners.get() + ")");
        check(refusals.size() == threads - 1,
                "every loser is refused (got " + refusals.size() + ")");
        boolean named = true;
        for (String held : refusals) {
            if (held == null || held.trim().isEmpty()) named = false;
        }
        check(named, "no refusal comes back without a holder name");
    }

    // ---- AwaitBox -------------------------------------------------------
    private static void awaitCases() throws Exception {
        // Never arrives: this is the controller-timeout refusal, and it must
        // return null only AFTER the deadline, never early.
        AwaitBox<String> never = new AwaitBox<>();
        long t0 = System.currentTimeMillis();
        String got = never.await(120, 20, null);
        long elapsed = System.currentTimeMillis() - t0;
        check(got == null, "a value that never arrives times out to null");
        check(elapsed >= 110, "the timeout waits out its deadline (waited " + elapsed + "ms)");

        // Already there: no wait at all.
        AwaitBox<String> early = new AwaitBox<>();
        early.set("CONTROLLER");
        t0 = System.currentTimeMillis();
        check("CONTROLLER".equals(early.await(5_000, 1_000, null)),
                "a value handed over before the wait returns immediately");
        check(System.currentTimeMillis() - t0 < 1_000,
                "...without burning the deadline");

        // Arrives late, from another thread: the hop landing at 40ms of a 2s
        // deadline is the normal successful case.
        final AwaitBox<String> late = new AwaitBox<>();
        new Thread(() -> {
            try {
                Thread.sleep(40);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            late.set("CONTROLLER");
        }).start();
        check("CONTROLLER".equals(late.await(2_000, 500, null)),
                "a value handed over from another thread wakes the waiter");

        // Progress must be reported while waiting, or a 30s wait looks like a hang.
        AwaitBox<String> quiet = new AwaitBox<>();
        final AtomicInteger ticks = new AtomicInteger(0);
        quiet.await(100, 20, msLeft -> ticks.incrementAndGet());
        check(ticks.get() >= 2, "the waiter is told how much deadline is left (got "
                + ticks.get() + " reports)");

        // A null handoff is not a value: it must not end the wait, or a receiver
        // that arrived without a controller would read as success.
        AwaitBox<String> nulled = new AwaitBox<>();
        nulled.set(null);
        check(nulled.peek() == null && nulled.await(60, 20, null) == null,
                "setting null is ignored and still times out");

        // clear() lets one coordinator serve several runs without a stale binder.
        AwaitBox<String> reused = new AwaitBox<>();
        reused.set("first");
        reused.clear();
        check(reused.await(60, 20, null) == null,
                "a cleared box does not hand out the previous run's value");

        // Interruption is a refusal that preserves the flag.
        final AwaitBox<String> interrupted = new AwaitBox<>();
        final String[] result = new String[1];
        final boolean[] flag = new boolean[1];
        Thread waiter = new Thread(() -> {
            result[0] = interrupted.await(5_000, 1_000, null);
            flag[0] = Thread.currentThread().isInterrupted();
        });
        waiter.start();
        Thread.sleep(50);
        waiter.interrupt();
        waiter.join(2_000);
        check(result[0] == null, "an interrupted wait refuses instead of returning a value");
        check(flag[0], "...and preserves the interrupt flag for the caller");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("[T] RunGuard / AwaitBox");
        guardCases();
        awaitCases();
        System.out.println("");
        System.out.println("RunHandoffTest: " + pass + "/" + (pass + fail) + " passed");
        if (fail != 0) System.exit(1);
    }
}
