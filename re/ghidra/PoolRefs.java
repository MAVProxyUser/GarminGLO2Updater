import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
// Find functions that load a literal-pool word equal to a given value; decompile them.
public class PoolRefs extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(a[0]));
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    Set<Function> fs = new LinkedHashSet<>();
    for (int i = 1; i < a.length; i++) {
      long v = Long.decode(a[i]);
      byte[] n = {(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
      Address f = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), n, null, true, monitor);
      while (f != null) {
        for (Reference r : getReferencesTo(f)) {
          Function fn = getFunctionContaining(r.getFromAddress());
          out.println("// value " + a[i] + " pool@" + f + " used by " + (fn == null ? r.getFromAddress() : fn.getName()));
          if (fn != null) fs.add(fn);
        }
        f = currentProgram.getMemory().findBytes(f.add(1), n, null, true, monitor);
      }
    }
    for (Function fn : fs) {
      out.println("// ===== " + fn.getName());
      DecompileResults r = di.decompileFunction(fn, 120, monitor);
      out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed");
    }
    out.close();
  }
}
