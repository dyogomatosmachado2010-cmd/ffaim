import re, sys

path = sys.argv[1]
pats = [p.lower() for p in sys.argv[2:]] or [
    'dyld', 'image', 'dylib', 'frida', 'substrate', 'jailbreak', 'jail',
    'tamper', 'checksum', 'integrity', 'cheat', 'hack', 'debug', 'ptrace',
    'sysctl', 'proc_', 'crypt', 'signature', 'inject', 'hook',
]

data = open(path, 'rb').read()
strs = re.findall(rb'[\x20-\x7e]{4,}', data)
seen = set()
hits = []
for s in strs:
    t = s.decode('latin-1')
    low = t.lower()
    for p in pats:
        if p in low:
            if t not in seen:
                seen.add(t)
                hits.append(t)
            break

print('strings: %d, filtradas: %d' % (len(strs), len(hits)))
for h in hits:
    print('   ', h[:150])
