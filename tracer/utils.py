import sys
import bisect

def print_lib_usage(trace_path, mappings_path):

    trace = open(trace_path,"r").read()
    mappings = open(mappings_path,"r").read()

    maps = []
    for line in mappings.split('\n'):
        if len(line)>1:
            name, start, end = line.split(" ")
            maps.append([int(start, 0), int(end, 0), name, 0])
    maps.sort()
    results = set()
    tot = 0
    for line in trace.split("\n"):
        line = line.replace("rip=", "pc=").replace("eip=", "pc=")
        if "pc=" in line:
            line = line.split("pc=")[1]
            line = line.split(",")[0]
            pc = int(line, 0)
            idx = bisect.bisect_left(maps, [pc, 0, "", 0])
            if idx > 0 and pc < maps[idx-1][1]:
                results.add(idx-1)
                maps[idx-1][3]+=1
            tot+=1

    last_table = []
    for idx in results:
        percent = 100*maps[idx][3]/tot
        last_table.append((percent, maps[idx][2]))

    last_table.sort()
    last_table = last_table[::-1]

    print("-------------")
    print("Libs breakdown for this trace :\n")
    for t in last_table:
        print(t[1]+(" (%.2f" % (t[0]))+"%)")
    print("-------------\n")