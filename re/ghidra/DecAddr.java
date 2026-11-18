import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
public class DecAddr extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(a[0]));
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    for (int i = 1; i < a.length; i++) {
      Address ad = toAddr(Long.decode(a[i]));
      Function f = getFunctionContaining(ad);
      if (f == null) { out.println("// no function at " + ad); continue; }
      StringBuilder callers = new StringBuilder();
      for (Reference r : getReferencesTo(f.getEntryPoint())) {
        Function c = getFunctionContaining(r.getFromAddress());
        callers.append(c == null ? r.getFromAddress().toString() : c.getName()).append(" ");
      }
      out.println("// ===== " + f.getName() + "  callers: " + callers);
      DecompileResults r = di.decompileFunction(f, 120, monitor);
      out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed");
    }
    out.close();
  }
}
