from EasyLogin import EL
import json
a=EL(cachedir="__pycache__")
#tag = "linux-4.19"
tag="gvisor"
res = {}
for part in ["", "fixed", "invalid"]:
    a.get(f"https://syzkaller.appspot.com/{tag}/{part}", result=True)
    tables = a.b.find_all("table", {"class":"list_table"})
    table = tables[1] if part=="" else tables[0]
    bugs=[]
    for tr in table.find_all("tr")[1:]:
        #url = tr.find("td",{"class":"title"}).find("a")["href"]
        title = tr.find("td",{"class":"title"}).text
        bugs.append(title)
    res[part]=bugs
open(f"syzbot_bugs_{tag}.json","w").write(json.dumps(res))