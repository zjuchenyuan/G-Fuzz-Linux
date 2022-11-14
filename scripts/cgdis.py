import sys
from runscinfo import *
id, version, func, filename = sys.argv[1:]
sys.tmp = []
called_map = load_edgefile(f"/g.linux/analyzer/build/lib/{version}/parsed_cg.txt")
fileid = json.load(open(f"/g.linux/analyzer/build/lib/{version}/fileid.json"))
target_funcs = [i for i in called_map if i.endswith("@"+func)]
print(target_funcs)
if len(target_funcs)>1:
    file_candidates = [i for i in fileid if i.endswith(filename)]
    assert len(file_candidates)==1, file_candidates
    fid = fileid[file_candidates[0]]
    target_funcs = [i for i in target_funcs if i.startswith(str(fid)+"@")]
assert len(target_funcs)==1, target_funcs
t = target_funcs[0]
print(t)
def filter_skip_toolong(item, callers, dis):
    if "@sys_" in item or "@__sys_" in item or "@__do_sys_" in item or "@vfs_" in item:
        sys.tmp.append([item, dis])
    #if dis>10:
    #    return []
    if len(sys.tmp)>10:
        return []
    return callers

x=bfs_search(called_map, t, show=True, filter_func=filter_skip_toolong)
res={}
func2pcs=json.load(open(f"/g.linux/analyzer/build/lib/{version}/func2pcs.json"))
for f, dis in x.items():
    if f not in func2pcs:
        print("error no func2pcs", f)
        continue
    for pc in func2pcs[f]:
        res[pc]=dis
print(id, "res:", len(res))
open(f"cgdis_{id}.json","w").write(json.dumps(res))