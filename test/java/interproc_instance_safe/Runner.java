// Instance-method callee. The Runtime.exec sink consumes ONLY the last
// parameter (cmd); the first parameter (label) never reaches the sink. This
// pins the inter-procedural argument->parameter mapping: a tainted last
// argument must map to `cmd` (param index 2, after the implicit `this`), not to
// `label` (the off-by-one that dropped every Java instance-method flow).
public class Runner {
    public void run(String label, String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd); // sink: only the last param
    }
}
