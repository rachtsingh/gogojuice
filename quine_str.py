import sys
import re
filename = sys.argv[1]

f = open(filename, 'r')
s = ''
for line in f:
    s = s + line.encode("string_escape").replace('"', r'\"')

print s

