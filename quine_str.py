import sys
import re
filename = sys.argv[1]

seed = "\\\"asdf\\\""

f = open(filename, 'r')
s = ''
for line in f:
    s = s + line.encode("string_escape").replace('"', r'\"')

s = s.replace(r"\'", "'").replace('%', '%%')
s = s.replace(seed, "%#v")
print s

