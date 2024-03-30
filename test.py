#!/usr/bin/env python3
import subprocess;
import os;
import shlex;

def cmd_run(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)));
    return subprocess.run(cmd, **kwargs);

if __name__ == '__main__':
    test_count = 0;
    success_count = 0;
    failed_count  = 0;
    for entry in os.scandir("./tests/"):
        porth_ext = ".porth";
        if entry.is_file() and entry.path.endswith(porth_ext):
            print("[INFO] Testing %s" % entry.path);
            sim_output = cmd_run(["./porth.py", "sim", entry.path], capture_output=True, check=True).stdout; 
            cmd_run(["./porth.py", "com", entry.path], check=True);
            com_output = cmd_run([entry.path[:-len(porth_ext)]], capture_output=True, check=True).stdout;
            test_count += 1;
            if sim_output != com_output:
                print("[ERROR]: Output discrepancy between simulation and compilation");
                print("  Simulation output:");
                print("    %s" % sim_output);
                print("  Compilation output:");
                print("    %s" % com_output);
                failed_count += 1;
                # TODO: don't exit on fail, just report
                exit(1);
            else:
                print("[INFO] %s OK" % entry.path);
                success_count += 1;
    print("\n-------------------------------\n");
    print("Exectured  : %s" % test_count);
    print("Failed     : %s" % failed_count);
    print("Successful : %s" % success_count);
