"""
Compare h2probe captures against a reference capture, GREASE and per-connection randomness normalized.
"""
import json
import sys


def is_grease(v: str) -> bool:
    """
    判定十六进制值是否为 GREASE
    """
    n = int(v, 16)
    return (n & 0x0f0f) == 0x0a0a and (n >> 8) == (n & 0xff)


def norm(values):
    """
    把列表里的 GREASE 统一成 G
    """
    return ['G' if is_grease(v) else v for v in values]


def static_bodies(ch):
    """
    抽出内容不随连接变化的扩展 body
    """
    volatile = {'0033', 'fe0d', '0029', '0015', '0000'}
    out = {}
    for e in ch['extensions']:
        if is_grease(e['id']):
            continue
        if e['id'] in volatile:
            out[e['id']] = f"len={e['len']}" if e['id'] == 'fe0d' else '*'
            continue
        out[e['id']] = e['data']
    return out


def describe(ch):
    """
    提取用于比较的指纹字段
    """
    return {
        'record_version': ch['record_version'],
        'client_version': ch['client_version'],
        'session_id_len': ch['session_id_len'],
        'ciphers': norm(ch['ciphers']),
        'compression': ch['compression'],
        'ext_set': sorted(norm([e['id'] for e in ch['extensions']])),
        'ext_order': norm([e['id'] for e in ch['extensions']]),
        'groups': norm(ch.get('supported_groups') or []),
        'key_shares': ['G' if is_grease(k.split('/')[0]) else k for k in ch.get('key_shares') or []],
        'sigalgs': norm(ch.get('sig_algs') or []),
        'versions': norm(ch.get('supported_versions') or []),
        'alpn': ch.get('alpn'),
        'bodies': static_bodies(ch),
        'ja4': ch.get('ja4'),
    }


def main():
    rows = [json.loads(line) for line in open('/root/h2probe/captures.jsonl')]
    ref = describe(rows[int(sys.argv[1])]['client_hello'])
    start = int(sys.argv[2])
    ignore_order = len(sys.argv) > 3 and sys.argv[3] == 'permuted'

    for i in range(start, len(rows)):
        ch = rows[i].get('client_hello')
        if ch is None:
            print(i, 'no client_hello', rows[i].get('error'))
            continue
        got = describe(ch)
        diffs = []
        for key, want in ref.items():
            if key == 'ext_order' and ignore_order:
                continue
            if key == 'bodies':
                for ext_id in sorted(set(want) | set(got['bodies'])):
                    if want.get(ext_id) != got['bodies'].get(ext_id):
                        diffs.append(f"  body {ext_id}: want {str(want.get(ext_id))[:80]} got {str(got['bodies'].get(ext_id))[:80]}")
                continue
            if got[key] != want:
                diffs.append(f'  {key}: want {want} got {got[key]}')
        grease_pos = [j for j, e in enumerate(ch['extensions']) if is_grease(e['id'])]
        print(i, got['ja4'], 'MATCH' if not diffs else 'DIFF', 'grease_ext_pos', grease_pos, 'order', ' '.join(got['ext_order']))
        for d in diffs:
            print(d)


if __name__ == '__main__':
    main()
