import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.RootEnvironment;
import com.polygraphene.df.reroot.RootReusePolicy;

/** Fail-closed verdict for the RMG execution path, never DFR acquisition. */
public final class RootReusePolicyTest {
    private static int count;

    private static void check(boolean ok, String why) {
        count++;
        if (!ok) throw new AssertionError(why);
    }

    private static RootEnvironment.Observation observed() {
        RootEnvironment.Observation o = new RootEnvironment.Observation();
        o.bootId = "19671080-6ce0-431e-a034-7b5c2b79e1d2";
        o.markerState = AutoRootPolicy.MARKER_UNKNOWN;
        o.dfrPostRootComplete = false;
        o.dfrPostRootUnreadable = true;
        o.persistentDaemon = RootEnvironment.DAEMON_UNKNOWN;
        o.loadedModule = RootEnvironment.MODULE_ATTESTED_RMG;
        o.selinuxEnforcing = true;
        return o;
    }

    private static boolean success(RootEnvironment.Observation o) {
        return RootReusePolicy.succeeded(RootEnvironment.classify(o));
    }

    public static void main(String[] args) {
        check(success(observed()), "physically observed RMG state succeeds despite unreadable local probes");
        check(!RootReusePolicy.succeeded(null), "missing verdict refuses");
        RootEnvironment.Observation o = observed();
        o.loadedModule = RootEnvironment.MODULE_UNKNOWN;
        check(!success(o), "missing provider attestation refuses");
        o = observed();
        o.loadedModule = RootEnvironment.MODULE_PRESENT_UNIDENTIFIED;
        check(!success(o), "module name is not a provider attestation");
        o = observed();
        o.loadedModule = RootEnvironment.MODULE_ATTESTED_DFR;
        check(!success(o), "incomplete DFR is not RMG execution");
        o = observed();
        o.selinuxEnforcing = false;
        check(!success(o), "SELinux not enforcing refuses");
        o = observed();
        o.bootId = "";
        check(!success(o), "unknown boot refuses");
        o = observed();
        o.dfrPostRootComplete = true;
        check(!success(o), "DFR acquisition is never represented as RMG reuse");
        o = observed();
        o.loadedModule = RootEnvironment.MODULE_ATTESTED_NONE;
        check(!success(o), "clean acquisition candidate is not RMG reuse");
        o = observed();
        o.loadedModule = RootEnvironment.MODULE_ATTESTED_RMG;
        check(!RootEnvironment.classify(o).dfrAcquired,
            "a completed RMG run never claims independent DFR acquisition");
        System.out.println("RootReusePolicyTest: " + count + "/" + count + " passed");
    }
}
