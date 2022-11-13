import os, sys
FOLDER=os.path.abspath(os.path.dirname(__file__))
def s(command):
    print("#", command)
    assert os.system(command)==0
def cd(folder):
    if not os.path.isdir(folder):
        os.makedirs(folder)
    os.chdir(folder)
assert open("/etc/hostname").read().strip()=="0efe18d9723b", "should run in the container"
cd("/data2/cy/deadline/work")
version = sys.argv[1]
configurl = sys.argv[2]
outfolder = f"/data2/cy/analyzer-for-test/build/lib/{version}"
if os.path.isfile(f"{outfolder}/fileid.json"):
    print("already finished")
    exit(0)
s(f"python3 main.py -t {version} checkout")
s(f"python3 main.py -t {version} config")
s(f"wget -O '/data2/cy/deadline/code/objs/linux-stable-{version}/.config' '{configurl}' ")
s(f"python3 main.py -t {version} build")
s(f"python3 main.py -t {version} parse")
s(f"python3 main.py -t {version} irgen")
os.makedirs(outfolder, exist_ok=True)
cd(outfolder)
s(f"find /data2/cy/deadline/code/bcfs/linux-stable-{version} -type f -name '*.bc' > bclist.txt")
s("../analyzer `cat bclist.txt`")
s("python3 /data2/cy/analyzer-for-test/parse_cgtxt.py ")