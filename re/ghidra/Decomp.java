// Decompile functions whose demangled names match regexes in a file.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class Decomp extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    List<String> pats = Files.readAllLines(Paths.get(a[0]));
    PrintWriter out = new PrintWriter(new FileWriter(a[1]));
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    SymbolTable st = currentProgram.getSymbolTable();
    List<Pattern> ps = new ArrayList<>();
    for (String p : pats) if (!p.trim().isEmpty()) ps.add(Pattern.compile(p.trim()));
    for (String p : pats) {
      p = p.trim();
      if (!p.startsWith("@")) continue;
      Address ad = toAddr(p.substring(1));
      Function f = getFunctionAt(ad);
      if (f == null) {
        new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
        new CreateFunctionCmd(ad).applyTo(currentProgram, monitor);
        f = getFunctionAt(ad);
      }
      if (f == null) { out.println("// FAILED " + p); continue; }
      DecompileResults r = di.decompileFunction(f, 120, monitor);
      out.println("// ===== " + f.getName() + " @ " + ad);
      if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
    }
    ps.removeIf(x -> x.pattern().startsWith("@"));
    SymbolIterator it = st.getAllSymbols(true);
    Set<Address> done = new HashSet<>();
    while (it.hasNext()) {
      Symbol s = it.next();
      String n = s.getName(true);
      boolean m = false;
      for (Pattern p : ps) if (p.matcher(n).find()) { m = true; break; }
      if (!m) continue;
      Address ad = s.getAddress();
      if (!ad.isMemoryAddress() || done.contains(ad)) continue;
      MemoryBlockCheck: {
        if (currentProgram.getMemory().getBlock(ad) == null || !currentProgram.getMemory().getBlock(ad).isExecute()) continue;
      }
      done.add(ad);
      Function f = getFunctionAt(ad);
      if (f == null) {
        new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
        new CreateFunctionCmd(ad).applyTo(currentProgram, monitor);
        f = getFunctionAt(ad);
      }
      if (f == null) { out.println("// FAILED create " + n + " @ " + ad); continue; }
      DecompileResults r = di.decompileFunction(f, 120, monitor);
      out.println("// ===== " + n + " @ " + ad);
      if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
      else out.println("// decompile failed: " + r.getErrorMessage());
      out.flush();
    }
    out.close();
  }
}
