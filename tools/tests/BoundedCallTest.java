import com.polygraphene.df.reroot.BoundedCall;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The hung case, which is the whole reason this class exists.
 *
 * A wedged remote cannot be produced on a device on demand, and a synchronous
 * binder transaction cannot be cancelled, so the only thing that can be proven
 * anywhere is the property the caller actually depends on: it returns at the
 * deadline whatever the work does. Proven here.
 */
public final class BoundedCallTest {
    private static int checks;

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    public static void main(String[] args) throws Exception {
        // --- the caller returns at the deadline on a hung call --------------
        final CountDownLatch release = new CountDownLatch(1);
        long started = System.nanoTime();
        BoundedCall.Result<String> hung = BoundedCall.run("test-hung", 150, () -> {
            release.await();              // never released before we return
            return "too late";
        });
        long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
        expect(hung.timedOut, "a call that never returns times out");
        expect(hung.value == null, "and yields no value");
        expect(!hung.completed(), "and is not completed");
        expect(elapsedMs < 5_000,
                "and the caller returned promptly (" + elapsedMs + "ms), not when the"
                        + " work did");
        /*
         * The late value must never reach the caller: it already returned, and
         * a result delivered afterwards would be a verdict from a call that
         * was abandoned.
         */
        release.countDown();
        Thread.sleep(50);
        expect(hung.value == null, "a late completion does not retroactively fill the result");

        // --- the ordinary paths --------------------------------------------
        BoundedCall.Result<String> ok = BoundedCall.run("test-ok", 5_000, () -> "value");
        expect(ok.completed() && "value".equals(ok.value), "work that finishes returns its value");
        expect(!ok.timedOut && ok.failure == null, "and reports neither timeout nor failure");

        // null is a value, not a timeout and not a failure
        BoundedCall.Result<String> nullValue = BoundedCall.run("test-null", 5_000, () -> null);
        expect(nullValue.completed(), "work returning null completed");
        expect(nullValue.value == null && !nullValue.timedOut && nullValue.failure == null,
                "and null is kept distinct from a timeout and from a failure");

        // a throwing call is its own outcome
        BoundedCall.Result<String> threw = BoundedCall.run("test-throw", 5_000, () -> {
            throw new IllegalStateException("boom");
        });
        expect(!threw.completed(), "work that throws did not complete");
        expect(!threw.timedOut, "and it is NOT reported as a timeout");
        expect(threw.failure instanceof IllegalStateException, "the cause survives");

        // --- degenerate inputs ----------------------------------------------
        BoundedCall.Result<String> noWork = BoundedCall.run("test-none", 1_000, null);
        expect(!noWork.completed() && !noWork.timedOut, "no work is a failure, not a timeout");
        final AtomicBoolean ran = new AtomicBoolean(false);
        BoundedCall.Result<String> zero = BoundedCall.run("test-zero", 0, () -> {
            ran.set(true);
            return "x";
        });
        expect(zero.timedOut && zero.value == null,
                "a non-positive deadline refuses rather than waiting forever");
        BoundedCall.Result<String> negative = BoundedCall.run("test-neg", -1, () -> "x");
        expect(negative.timedOut, "so does a negative one");

        // --- the worker must not keep a process alive -----------------------
        BoundedCall.run("test-daemon", 120, () -> {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException ignored) {
                // nothing
            }
            return "x";
        });
        boolean foundNonDaemon = false;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if ("test-daemon".equals(t.getName()) && !t.isDaemon()) foundNonDaemon = true;
        }
        expect(!foundNonDaemon,
                "the abandoned worker is a daemon thread; a leaked non-daemon one would"
                        + " hold the process open");

        System.out.println("BoundedCallTest: " + checks + "/" + checks + " passed");
    }
}
