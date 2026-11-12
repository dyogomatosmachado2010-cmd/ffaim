import re, sys, os, zipfile, struct

# procura endpoints de rede nos binarios do bundle: urls, hosts, ips, portas.
# le do IPA original para nao depender do app extraido.

IPA = sys.argv[1] if len(sys.argv) > 1 else r'FreeFire(IOS).ipa'
TARGETS = [
    'Payload/freefireth.app/freefireth',
    'Payload/freefireth.app/Data/Managed/Metadata/global-metadata.dat',
    'Payload/freefireth.app/Frameworks/libac_sdk.dylib',
]

z = zipfile.ZipFile(IPA)

url_re = re.compile(rb'(?:https?|wss?|tcp|udp)://[A-Za-z0-9\.\-_:/%\?=&@\+~]{4,120}')
host_re = re.compile(rb'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|br|xyz|top|club|site|online|app|dev|me|gg|co|info|ru|cn|tk|ml|ga|cf|gq|vip|cc|tv|shop|store|live|link|fun|space|website|host|press|icu|buzz|monster|click|pro)\b', re.I)
ip_re = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')

def scan(name, data):
    print('=' * 78)
    print('%s  (%d bytes)' % (name, len(data)))

    urls = sorted(set(m.group(0).decode('latin-1') for m in url_re.finditer(data)))
    print('-- urls (%d) --' % len(urls))
    for u in urls[:80]:
        print('   ', u)

    hosts = {}
    for m in host_re.finditer(data):
        h = m.group(0).decode('latin-1').lower()
        hosts[h] = hosts.get(h, 0) + 1
    print('-- hosts (%d unicos) --' % len(hosts))
    for h, c in sorted(hosts.items(), key=lambda kv: -kv[1])[:80]:
        print('    %-52s x%d' % (h, c))

    ips = {}
    for m in ip_re.finditer(data):
        s = m.group(0).decode('latin-1')
        ips[s] = ips.get(s, 0) + 1
    print('-- ips (%d unicos) --' % len(ips))
    for s, c in sorted(ips.items(), key=lambda kv: -kv[1])[:40]:
        print('    %-18s x%d' % (s, c))

for t in TARGETS:
    try:
        data = z.read(t)
    except KeyError:
        print('ausente:', t)
        continue
    scan(t.split('/')[-1], data)
