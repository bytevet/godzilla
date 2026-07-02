// JavaDump is Godzilla's embedded Java frontend helper, run as a single-file
// source program: `java JavaDump.java <path> [path...]`. Each path is a .java
// source file (compiled in-process with the system compiler), a .class file, or
// a directory (walked for both). It prints a JSON document describing every
// method's bytecode to stdout, which converters/java/lower.go lowers to gIR.
//
// Requires JDK 24+ for the standard java.lang.classfile API (no external deps).
// Self-contained (JDK-only-API) sources compile standalone; sources that need a
// classpath should be scanned as compiled .class/.jar instead.
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import java.lang.classfile.*;
import java.lang.classfile.attribute.*;
import java.lang.classfile.constantpool.*;
import java.lang.classfile.instruction.*;
import java.lang.constant.*;
import javax.tools.*;

public class JavaDump {
    public static void main(String[] args) throws Exception {
        List<byte[]> classes = new ArrayList<>();
        Path tmp = Files.createTempDirectory("gjdump");
        List<String> sources = new ArrayList<>();
        for (String a : args) collect(Path.of(a), sources, classes);
        if (!sources.isEmpty()) {
            JavaCompiler c = ToolProvider.getSystemJavaCompiler();
            List<String> opts = new ArrayList<>(List.of("-d", tmp.toString(), "-proc:none", "-g"));
            opts.addAll(sources);
            // Best-effort: unresolved classpath deps make javac emit no .class; those
            // sources are simply skipped (scan compiled artifacts for full fidelity).
            c.run(null, null, OutputStream.nullOutputStream(), opts.toArray(new String[0]));
            try (var w = Files.walk(tmp)) {
                for (Path p : (Iterable<Path>) w.filter(x -> x.toString().endsWith(".class"))::iterator)
                    classes.add(Files.readAllBytes(p));
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"classes\":[");
        boolean firstClass = true;
        for (byte[] bytes : classes) {
            ClassModel cm;
            try { cm = ClassFile.of().parse(bytes); } catch (Throwable t) { continue; }
            if (!firstClass) sb.append(',');
            firstClass = false;
            dumpClass(cm, sb);
        }
        sb.append("]}");
        System.out.println(sb);
    }

    static void collect(Path p, List<String> sources, List<byte[]> classes) throws IOException {
        if (Files.isDirectory(p)) {
            try (var w = Files.walk(p)) {
                for (Path x : (Iterable<Path>) w.filter(Files::isRegularFile)::iterator) collect(x, sources, classes);
            }
        } else {
            String s = p.toString();
            if (s.endsWith(".java")) sources.add(s);
            else if (s.endsWith(".class")) classes.add(Files.readAllBytes(p));
        }
    }

    static void dumpClass(ClassModel cm, StringBuilder sb) {
        sb.append("{\"name\":").append(jstr(cm.thisClass().asInternalName())).append(",\"methods\":[");
        boolean first = true;
        for (MethodModel mm : cm.methods()) {
            if (!first) sb.append(',');
            first = false;
            dumpMethod(cm, mm, sb);
        }
        sb.append("]}");
    }

    static void dumpMethod(ClassModel cm, MethodModel mm, StringBuilder sb) {
        boolean isStatic = (mm.flags().flagsMask() & java.lang.reflect.Modifier.STATIC) != 0;
        sb.append("{\"name\":").append(jstr(mm.methodName().stringValue()))
          .append(",\"descriptor\":").append(jstr(mm.methodType().stringValue()))
          .append(",\"static\":").append(isStatic)
          .append(",\"instrs\":[");
        var codeOpt = mm.code();
        if (codeOpt.isPresent()) {
            boolean first = true;
            int line = 0;
            for (CodeElement e : codeOpt.get()) {
                if (e instanceof LineNumber ln) { line = ln.line(); continue; }
                if (!(e instanceof Instruction instr)) continue;
                String rec = dumpInstr(instr, line);
                if (rec == null) continue;
                if (!first) sb.append(',');
                first = false;
                sb.append(rec);
            }
        }
        sb.append("]}");
    }

    static String dumpInstr(Instruction instr, int line) {
        String pos = ",\"line\":" + line;
        if (instr instanceof InvokeInstruction i) {
            return "{\"op\":\"INVOKE\",\"kind\":" + jstr(i.opcode().name())
                + ",\"owner\":" + jstr(i.owner().asInternalName())
                + ",\"mname\":" + jstr(i.name().stringValue())
                + ",\"mdesc\":" + jstr(i.type().stringValue()) + pos + "}";
        }
        if (instr instanceof InvokeDynamicInstruction i) {
            return "{\"op\":\"INVOKEDYNAMIC\",\"mname\":" + jstr(i.name().stringValue())
                + ",\"mdesc\":" + jstr(i.type().stringValue()) + pos + "}";
        }
        if (instr instanceof LoadInstruction i)
            return "{\"op\":\"LOAD\",\"slot\":" + i.slot() + pos + "}";
        if (instr instanceof StoreInstruction i)
            return "{\"op\":\"STORE\",\"slot\":" + i.slot() + pos + "}";
        if (instr instanceof ConstantInstruction i) {
            Object v = i.constantValue();
            String s = (v instanceof String) ? jstr((String) v) : jstr(String.valueOf(v));
            return "{\"op\":\"CONST\",\"cst\":" + s + pos + "}";
        }
        if (instr instanceof FieldInstruction i)
            return "{\"op\":\"FIELD\",\"kind\":" + jstr(i.opcode().name())
                + ",\"owner\":" + jstr(i.owner().asInternalName())
                + ",\"fname\":" + jstr(i.name().stringValue())
                + ",\"fdesc\":" + jstr(i.type().stringValue()) + pos + "}";
        if (instr instanceof NewObjectInstruction i)
            return "{\"op\":\"NEW\",\"type\":" + jstr(i.className().asInternalName()) + pos + "}";
        if (instr instanceof NewReferenceArrayInstruction i)
            return "{\"op\":\"NEWARRAY\"" + pos + "}";
        if (instr instanceof NewPrimitiveArrayInstruction i)
            return "{\"op\":\"NEWARRAY\"" + pos + "}";
        if (instr instanceof ArrayLoadInstruction i)
            return "{\"op\":\"ARRAYLOAD\"" + pos + "}";
        if (instr instanceof ArrayStoreInstruction i)
            return "{\"op\":\"ARRAYSTORE\"" + pos + "}";
        if (instr instanceof OperatorInstruction i)
            return "{\"op\":\"OPERATOR\",\"kind\":" + jstr(i.opcode().name()) + pos + "}";
        if (instr instanceof ConvertInstruction i)
            return "{\"op\":\"CONVERT\"" + pos + "}";
        if (instr instanceof StackInstruction i)
            return "{\"op\":\"STACK\",\"kind\":" + jstr(i.opcode().name()) + pos + "}";
        if (instr instanceof TypeCheckInstruction i)
            return "{\"op\":\"TYPECHECK\",\"kind\":" + jstr(i.opcode().name()) + pos + "}";
        if (instr instanceof ReturnInstruction i)
            return "{\"op\":\"RETURN\",\"kind\":" + jstr(i.opcode().name()) + pos + "}";
        if (instr instanceof ThrowInstruction i)
            return "{\"op\":\"THROW\"" + pos + "}";
        if (instr instanceof BranchInstruction i)
            return "{\"op\":\"BRANCH\",\"kind\":" + jstr(i.opcode().name()) + pos + "}";
        if (instr instanceof IncrementInstruction i)
            return "{\"op\":\"NOP\"" + pos + "}"; // iinc: no stack effect
        if (instr instanceof NopInstruction i)
            return "{\"op\":\"NOP\"" + pos + "}";
        // Everything else (switches, monitor, etc.): emit opcode name; the Go
        // simulator applies a stack-delta table so unmodeled ops stay consistent.
        return "{\"op\":\"OTHER\",\"kind\":" + jstr(instr.opcode().name()) + pos + "}";
    }

    static String jstr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }
}
