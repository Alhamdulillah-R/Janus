"""
Turn one h2probe capture row into a janus_probe spec file.
"""
import json
import sys


def is_grease(v: int) -> bool:
    """
    判定 v 是否为 RFC 8701 GREASE 值
    """
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def token(hex_value: str) -> str:
    """
    GREASE 写成 grease, 其他原样
    """
    if is_grease(int(hex_value, 16)):
        return 'grease'
    return hex_value


def main():
    capture_path = '/root/h2probe/captures.jsonl'
    rows = [json.loads(line) for line in open(capture_path)]
    row = rows[int(sys.argv[1])]
    ch = row['client_hello']

    # OpenSSL 自己能构造且内容一致的扩展, 其余一律 raw
    native = {
        '0000', '000a', '000d', '0010', '0017', '0023', '002b',
        '002d', '0033', 'ff01', '0005', '001b', 'fe0d', '0015', '0029',
    }

    lines = [
        'ciphers ' + ' '.join(token(c) for c in ch['ciphers']),
        'extensions ' + ' '.join(token(e['id']) for e in ch['extensions']),
    ]
    if ch.get('supported_groups'):
        lines.append('groups ' + ' '.join(token(g) for g in ch['supported_groups']))
    if ch.get('key_shares'):
        lines.append('key_shares ' + ' '.join(token(k.split('/')[0]) for k in ch['key_shares']))
    if ch.get('sig_algs'):
        lines.append('sigalgs ' + ' '.join(token(s) for s in ch['sig_algs']))
    if ch.get('supported_versions'):
        lines.append('versions ' + ' '.join(token(v) for v in ch['supported_versions']))
    if ch.get('alpn'):
        lines.append('alpn ' + ' '.join(ch['alpn']))

    comp_ids = {'0001': '1', '0002': '2', '0003': '3'}
    if ch.get('cert_compression'):
        lines.append('cert_comp ' + ' '.join(comp_ids[c] for c in ch['cert_compression'] if c in comp_ids))

    for e in ch['extensions']:
        if is_grease(int(e['id'], 16)) or e['id'] in native:
            continue
        lines.append(f"raw {e['id']} {e['data']}".rstrip())

    ids = [e['id'] for e in ch['extensions']]
    if 'fe0d' in ids:
        lines.append('ech_grease')
    if '0005' in ids:
        lines.append('ocsp')
    if len(sys.argv) > 2 and sys.argv[2] == 'permute':
        lines.append('flag permute')

    print('\n'.join(lines))


if __name__ == '__main__':
    main()
