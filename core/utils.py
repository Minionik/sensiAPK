import subprocess

def run(cmd):
    try:
        return subprocess.getoutput(cmd)
    except:
        return ""