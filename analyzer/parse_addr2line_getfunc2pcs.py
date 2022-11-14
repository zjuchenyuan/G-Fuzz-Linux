import csv, json, gzip, os
folder = os.getcwd()
version = "4.19"+folder.split("4.19")[1]
print(version)
pc = None
cur_func = None
fileids = json.load(open(f"/g.linux/analyzer/build/lib/{version}/fileid.json"))

data = {}
def parseit(fileid, cur_func, pc):
    key = f"{fileid}@{cur_func}"
    pc = hex( int(pc[-8:],16)+5 )
    data.setdefault(key, []).append(pc)

errors = set()

for line in gzip.open(f"/g.linux/deadline/code/objs/linux-stable-{version}/allpcs_addr2line.txt.gz", "rt"):
    if line.startswith("0x"):
        pc = line.strip()
    elif line.startswith("/g.linux"):
        file = line.split(":")[0].replace("/g.linux/deadline/code/","")
        if file not in fileids:
            if file not in errors:
                print("[skip] not exist file:", file)
                errors.add(file)
            continue
        fileid = fileids[file]
        parseit(fileid, cur_func, pc)
    else:
        cur_func = line.strip()
open(f"/g.linux/analyzer/build/lib/{version}/func2pcs.json", "w").write(json.dumps(data))