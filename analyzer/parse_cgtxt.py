import csv, json, gzip
r = csv.reader(open("CG_sheet.csv"))
header = next(r)
_filename2id = {}
curid = 0
def filename2id(filename):
    global curid
    if filename not in _filename2id:
        _filename2id[filename] = curid
        curid+=1
    return _filename2id[filename]
fp = gzip.open("parsed_cg.txt.gz", "wt")
buffer = []
buffer2 = []
for line in r:
    caller, caller_filename, caller_line, isindirect, callee, callee_filename, callee_lineno = line
    caller_fileid, callee_fileid = filename2id(caller_filename), filename2id(callee_filename)
    buffer.append(f"{isindirect}\t{caller_fileid}@{caller}\t{callee_fileid}@{callee}\n")
    if isindirect=="no":
        buffer2.append(f"{isindirect}\t{caller_fileid}@{caller}\t{callee_fileid}@{callee}\n")
    if len(buffer)>100000:
        fp.write("".join(buffer))
        buffer = []
if buffer:
    fp.write("".join(buffer))
fp.close()
gzip.open("parsed_cg_noindirect.txt.gz", "wt").write("".join(buffer2))
open("fileid.json", "w").write(json.dumps(_filename2id))