# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Lossless synthetic fixtures using Python stdlib gzip and RFC1924 Base85.

Encoding avoids shipping plaintext fixture literals; it is not confidentiality.
No decoder output or fixture contents are printed. No runtime dependency fetch.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import zlib

MAGIC = b'CAVIAR-FIXTURE-B85-GZIP-1\n'
CAP = 32 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path):
    with path.open('rb') as stream:
        data = stream.read(CAP + 1)
    if len(data) > CAP:
        raise ValueError('fixture size cap')
    return data


def unpack(data):
    if data[:4] != b'\x1f\x8b\x08\x00':
        raise ValueError('gzip header/flags')
    obj = zlib.decompressobj(-zlib.MAX_WBITS)
    raw = obj.decompress(data[10:], CAP + 1)
    if len(raw) > CAP:
        raise ValueError('decoded size cap')
    if not obj.eof or len(obj.unused_data) != 8:
        raise ValueError('single gzip member required')
    if gzip.decompress(data) != raw:
        raise ValueError('gzip integrity')
    return raw


def encode(data):
    payload = base64.b85encode(data)
    return MAGIC + b'\n'.join(payload[i:i + 80] for i in range(0, len(payload), 80)) + b'\n'


def decode(encoded):
    if not encoded.startswith(MAGIC):
        raise ValueError('fixture encoding magic')
    try:
        data = base64.b85decode(b''.join(encoded[len(MAGIC):].splitlines()))
    except ValueError:
        raise ValueError('invalid Base85 fixture') from None
    if encode(data) != encoded:
        raise ValueError('noncanonical fixture encoding')
    return data


def verify(artifact, metadata):
    if set(metadata) != {'schema', 'encoding', 'encoded_sha256', 'decoded_sha256', 'decoded_bytes', 'seeds'}:
        raise ValueError('fixture manifest schema')
    if metadata['schema'] != 1 or metadata['encoding'] != 'gzip-base85-v1':
        raise ValueError('fixture encoding version')
    encoded = bounded_read(artifact)
    if digest(encoded) != metadata['encoded_sha256']:
        raise ValueError('encoded fixture hash')
    raw = unpack(decode(encoded))
    if digest(raw) != metadata['decoded_sha256'] or len(raw) != metadata['decoded_bytes']:
        raise ValueError('decoded fixture identity')
    if len(raw.splitlines()) != metadata['seeds']:
        raise ValueError('fixture seed count')
    return raw


def write_new(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def materialize(root, artifact, metadata, destination):
    # Generated plaintext must remain outside the tracked source tree.
    root = root.resolve(strict=True)
    relative = destination.absolute().relative_to(root)
    if not relative.parts or relative.parts[0] != 'tmp' or '..' in relative.parts:
        raise ValueError('fixture output must be under root/tmp')
    parent = root
    for part in relative.parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError('fixture output symlink')
        parent.mkdir(exist_ok=True)
    raw = verify(artifact, metadata)
    write_new(parent / relative.parts[-1], raw)
    return {'decoded_sha256': digest(raw), 'decoded_bytes': len(raw), 'seeds': metadata['seeds']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    enc = sub.add_parser('encode')
    enc.add_argument('--source', type=Path, required=True)
    enc.add_argument('--expected-sha256', required=True)
    enc.add_argument('--artifact', type=Path, required=True)
    enc.add_argument('--manifest', type=Path, required=True)
    dec = sub.add_parser('materialize')
    dec.add_argument('--root', type=Path, required=True)
    dec.add_argument('--artifact', type=Path, required=True)
    dec.add_argument('--manifest', type=Path, required=True)
    dec.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'encode':
        packed = bounded_read(args.source)
        raw = unpack(packed)
        if digest(raw) != args.expected_sha256:
            raise ValueError('published fixture pin mismatch')
        encoded = encode(packed)
        metadata = {'schema': 1, 'encoding': 'gzip-base85-v1', 'encoded_sha256': digest(encoded),
                    'decoded_sha256': digest(raw), 'decoded_bytes': len(raw), 'seeds': len(raw.splitlines())}
        write_new(args.artifact, encoded)
        write_new(args.manifest, (json.dumps(metadata, indent=2) + '\n').encode())
        print(json.dumps(metadata))
    else:
        metadata = json.loads(bounded_read(args.manifest))
        print(json.dumps(materialize(args.root, args.artifact, metadata, args.output)))


if __name__ == '__main__':
    main()
