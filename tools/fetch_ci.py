#!/usr/bin/env python3
"""fetch_ci.py - pega o ffaim.dylib que o GitHub Actions publicou no branch ci-log.

o artifact do Actions exige token; o CI tambem commita o dylib no branch ci-log,
entao da pra baixar com o git normal.

uso:
  python tools/fetch_ci.py                 # espera o run do HEAD terminar
  python tools/fetch_ci.py --no-wait       # so tenta pegar o que ja existe
  python tools/fetch_ci.py --out cheat/ffaim.dylib
"""
import argparse, json, os, subprocess, sys, time, urllib.request

REPO = 'dyogomatosmachado2010-cmd/ffaim'
BRANCH = 'ci-log'


def git(*args, **kw):
    return subprocess.run(['git'] + list(args), capture_output=True, text=True, **kw)


def api(path):
    req = urllib.request.Request('https://api.github.com/repos/%s%s' % (REPO, path),
                                 headers={'Accept': 'application/vnd.github+json',
                                          'User-Agent': 'ffaim'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def head_sha():
    out = git('rev-parse', 'HEAD').stdout.strip()
    return out


def latest_run():
    runs = api('/actions/runs?per_page=5')['workflow_runs']
    sha = head_sha()
    for w in runs:
        if w['head_sha'] == sha:
            return w
    return runs[0] if runs else None


def wait(run, timeout=1800):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        w = api('/actions/runs/%d' % run['id'])
        st = (w['status'], w['conclusion'])
        if st != last:
            print('  run %d: %s/%s' % (w['id'], w['status'], w['conclusion']))
            last = st
        if w['status'] == 'completed':
            return w
        time.sleep(20)
    return None


def fetch_dylib(out):
    print('git fetch origin %s' % BRANCH)
    r = git('fetch', 'origin', BRANCH, '--force')
    if r.returncode != 0:
        print(r.stderr.strip())
        return False
    r = subprocess.run(['git', 'cat-file', 'blob', 'FETCH_HEAD:ci-logs/ffaim.dylib'],
                       capture_output=True)
    if r.returncode != 0:
        print('  sem ci-logs/ffaim.dylib no branch (run ainda nao publicou?)')
        return False
    data = r.stdout
    if not data.startswith(b'\xcf\xfa\xed\xfe'):
        print('  blob nao e Mach-O (%d bytes)' % len(data))
        return False
    os.makedirs(os.path.dirname(os.path.abspath(out)) or '.', exist_ok=True)
    with open(out, 'wb') as f:
        f.write(data)
    print('  escrito %s (%d bytes)' % (out, len(data)))
    return True


def show_log():
    r = subprocess.run(['git', 'cat-file', 'blob', 'FETCH_HEAD:ci-logs/dylib.log'],
                       capture_output=True)
    if r.returncode == 0 and r.stdout:
        print('--- dylib.log (ultimas linhas) ---')
        for line in r.stdout.decode('utf8', 'replace').strip().splitlines()[-25:]:
            print('  ' + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='cheat/ffaim.dylib')
    ap.add_argument('--no-wait', action='store_true')
    a = ap.parse_args()

    run = latest_run()
    if not run:
        print('nenhum run encontrado')
        return 1
    print('run %d (%s) %s' % (run['id'], run['head_sha'][:7], run['status']))
    if not a.no_wait and run['status'] != 'completed':
        run = wait(run)
        if not run:
            print('timeout esperando o run')
            return 1
    print('conclusao: %s' % run['conclusion'])

    ok = fetch_dylib(a.out)
    show_log()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
