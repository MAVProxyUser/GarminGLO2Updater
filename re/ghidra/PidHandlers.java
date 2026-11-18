import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class PidHandlers extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outPath = a[0];
        Set<Long> pids = new HashSet<>();
        for (String s : a[1].split(",")) pids.add(Long.decode(s));
        List<Address> extraRefs = new ArrayList<>();
        for (int i = 2; i < a.length; i++) extraRefs.add(toAddr(Long.decode(a[i])));
        Listing L = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Function, Set<String>> hits = new LinkedHashMap<>();
        InstructionIterator it = L.getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString().toLowerCase();
            if (!m.startsWith("cmp") && !m.startsWith("mov") && !m.startsWith("sub") && !m.startsWith("teq")) continue;
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object o : ins.getOpObjects(op)) {
                    if (o instanceof Scalar && pids.contains(((Scalar) o).getUnsignedValue())) {
                        Function f = fm.getFunctionContaining(ins.getAddress());
                        if (f != null) hits.computeIfAbsent(f, k -> new TreeSet<>()).add(m + " " + ((Scalar) o).getUnsignedValue());
                    }
                }
            }
        }
        for (Address ea : extraRefs) {
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(ea)) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f != null) hits.computeIfAbsent(f, k -> new TreeSet<>()).add("ref " + ea);
            }
            // also literal-pool words equal to the address
            Memory: {
                byte[] needle = new byte[]{(byte) ea.getOffset(), (byte) (ea.getOffset() >> 8), (byte) (ea.getOffset() >> 16), (byte) (ea.getOffset() >> 24)};
                Address found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), needle, null, true, monitor);
                while (found != null) {
                    for (Reference r : currentProgram.getReferenceManager().getReferencesTo(found)) {
                        Function f = fm.getFunctionContaining(r.getFromAddress());
                        if (f != null) hits.computeIfAbsent(f, k -> new TreeSet<>()).add("pool@" + found + " -> " + ea);
                    }
                    found = currentProgram.getMemory().findBytes(found.add(1), needle, null, true, monitor);
                }
            }
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.println("// functions: " + fm.getFunctionCount());
            for (Map.Entry<Function, Set<String>> e : hits.entrySet()) {
                Function f = e.getKey();
                if (f.getBody().getNumAddresses() > 6000) { w.println("// skip huge " + f.getName()); continue; }
                w.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + "  hits: " + e.getValue());
                DecompileResults r = d.decompileFunction(f, 120, monitor);
                w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed: " + r.getErrorMessage());
            }
        }
    }
}
