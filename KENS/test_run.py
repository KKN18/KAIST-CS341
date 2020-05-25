import subprocess
import sys
import re

def check(printr = False):
    #proc = subprocess.Popen(['build/testTCP', '--gtest_filter=TestEnv_Any.TestTransfer_Accept_Recv_EOF'], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    #proc = subprocess.Popen(['build/testTCP', '--gtest_filter=TestEnv_Any.TestClose_Connect_CloseSimultaneous'], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    proc =subprocess.Popen(['make', 'test_part3'], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    err = proc.stderr.read()

    t = proc.stdout.read()
    err = proc.stderr.read()
    if "FAIL" in t:
        print(t)
        return 1
    if len(err) > 0:
        print(t)
        print(err)
        return 1
    return 0

if __name__ == "__main__":
    if len(sys.argv) == 2:
        check(printr = True)
    else:
        suc = 0
        fail = 0
        for i in range(100):
            print("run #%d (Current Success/Fail : %d/%d)" % (i+1, suc, fail))
            t = check()
            if t == 0:
                suc += 1
                print("Success")
            else:
                fail += 1
        print("Suc / Failed : %d / %d, rate=%f" % (suc, fail, float(suc)/(suc+fail)))
    
