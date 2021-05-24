"""Generate a C callgraph, excluding standard library functions.

python callgraph.py | dot -T png -o callgraph.png
"""
import subprocess
import re
import sys

subprocess.check_call(
    'clang -S -emit-llvm darkhttpd.c -o - | opt -analyze -dot-callgraph',
    shell=True, stdout=subprocess.PIPE
)
labels = {}
edges = {}
for line in open('callgraph.dot'):
    m = re.match('\t(\w+) .*label=\"{([\w ]+)}\"', line)
    if m:
        labels[m.group(2)] = m.group(1)
    m = re.match('\t(\w+) -> (\w+);', line)
    if m:
        edges[m.group(1)] = m.group(2)

unknown_node = edges[labels['exit']]
sys.stderr.write('unknown node is {}\n'.format(unknown_node))
external_node = labels['external node']
ignored_nodes = {unknown_node, external_node}
for a, b in edges.items():
    if b == unknown_node:
        ignored_nodes.add(a)

for line in open('callgraph.dot'):
    results = re.findall('(Node0x\w+)', line)
    if not results:
        print(line, end='')
    elif not any(m in ignored_nodes for m in results):
        print(line, end='')
