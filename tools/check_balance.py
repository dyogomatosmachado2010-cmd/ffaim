import re, os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cheat'))
for f in ('ffaim.mm', 'ffpanel.mm', 'ffaim.h', 'ff_offsets.h'):
    s = open(f, encoding='utf8').read()
    s2 = re.sub(r'//[^\n]*', '', s)
    s2 = re.sub(r'/\*.*?\*/', '', s2, flags=re.S)
    s2 = re.sub(r'"(?:\\.|[^"\\])*"', '""', s2)
    print('%-14s chaves %d/%d  parens %d/%d  colch %d/%d  @interface %d  @implementation %d  @end %d' % (
        f, s2.count('{'), s2.count('}'), s2.count('('), s2.count(')'),
        s2.count('['), s2.count(']'),
        len(re.findall(r'@interface', s)), len(re.findall(r'@implementation', s)),
        len(re.findall(r'@end', s))))
