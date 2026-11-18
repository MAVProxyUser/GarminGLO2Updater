import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
public class Disasm extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(a[0], true));
    for (int i = 1; i < a.length; i += 2) {
      Address s = toAddr(Long.decode(a[i]));
      int n = Integer.parseInt(a[i + 1]);
      out.println("---- " + s);
      Instruction ins = getInstructionAt(s);
      for (int k = 0; k < n && ins != null; k++, ins = ins.getNext()) out.println(ins.getAddress() + "  " + ins);
    }
    out.close();
  }
}
