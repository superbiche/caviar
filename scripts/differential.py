#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bounded deterministic Go-worker/Python differential campaign, streamed."""
import argparse
import hashlib
import gzip
import importlib.util
import json
from pathlib import Path
import random
import sys
import time

from caviar_redact import Client, CaviarError
from caviar_redact.client import _manifest_identity

ROOT = Path(__file__).resolve().parents[1]
SEED = 0xCA6106
CASES = 10000
TEXT_CAP = 65536


def generate(rng, i, corpus_inputs):
    keys = ("API_KEY", "API_KEY_v2", "sampled_token_ids", "api_key", "apiKey", "self.token", "secret_key_old", "db_password", "tokenizer", "token_count", "token2", "nTOKEN", "private_key_pem", "access_key", "credentialToRevoke", "ſecret", "API_KEY", "APı_KEY")
    values = ("Ab3xyz9Q", "abc(def)", "os.environ[", "config.get(", "str(process.env.TOKEN)", "$(cat", "Optional[str]", "self.token", "api_key)", "Deno.env.get(", "settings.TOKEN", "System.getenv<String>()", "get_random_secret_key()", "this?.token", "app.config.get<T>()", "random.path()", "Environment.TOKEN||fallback")
    separators = ("=", ":", " = ", ":\t")
    prefixes = ("", " ", "\n", "α", "-", "export ", "const\t", "conſt ", "\\n", "\\t", "\\token:")
    quote = rng.choice(("", "'", '"', '\\"'))
    value = rng.choice(values)
    kind = i % 8
    if i % 5 == 0:
        text = rng.choice(corpus_inputs)
        for _ in range(rng.randrange(1, 4)):
            position = rng.randrange(len(text) + 1)
            change = rng.choice(("\n", "\\n", "α", "ſ", "K", "-", "'", '"', " ", "token_", "API_KEY="))
            text = text[:position] + change + text[position + rng.randrange(2):]
    elif kind == 0:
        text = rng.choice(prefixes) + rng.choice(keys) + rng.choice(separators) + quote + value + quote
    elif kind == 1:
        text = rng.choice(("", " ", "α", "foo", "\\n", "\\t", "262144")) + rng.choice(("-", "--", "---")) + rng.choice(("", "my_", "new-", "word_" * rng.randrange(1, 40))) + rng.choice(("token", "secret", "api_key", "ſecret")) + rng.choice(("=", " ")) + quote + value + quote
    elif kind == 2:
        text = rng.choice(("Bearer ", "bearer\t", "TOKEN ")) + "aB7x" * rng.randrange(1, 10) + rng.choice(("", "=", "==", "α"))
    elif kind == 3:
        text = "https://example.invalid/" + rng.choice(("?", "#", "&", "&amp;", "&#38;", "\\u0026")) + rng.choice(("key", "auth", "pwd", "sig", "X-Amz-Signature", "ordinary")) + "=" + quote + value + quote
    elif kind == 4:
        text = rng.choice(("Cookie", "Authorization", "X-Api-Key")) + ": " + quote + rng.choice(("ordinary prose sentence", "two words", "three-letter ordinary words!", value, "Bearer " + value)) + quote
    elif kind == 5:
        text = json.dumps({rng.choice(keys): value, "ordinary": rng.choice(values)}, ensure_ascii=rng.choice((True, False)))
        for _ in range(rng.randrange(4)):
            text = json.dumps(text)
    elif kind == 6:
        text = rng.choice(prefixes) + rng.choice(keys) + "=" + "wrap(" * rng.randrange(1, 100) + rng.choice(values) + ")" * rng.randrange(1, 100)
    else:
        alphabet = "abcDEF019_.-=:;()[]{}'\"\\ \t\nαſKıİ"
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 256)))
    if i % 137 == 0:
        text += "\n" + "token_ids " * 256
    assert len(text.encode()) <= TEXT_CAP
    return text


def run(output, reference):
    pins = json.loads((ROOT / "docs/UPSTREAM.json").read_text())
    reference = reference or ROOT / "tmp/fixtures/redact-v7-reference.py"
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == pins["reference_sha256"], "reference mismatch"
    spec = importlib.util.spec_from_file_location("caviar_diff_reference", reference)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    package = Path(sys.modules["caviar_redact"].__file__).resolve().parent
    assert package.is_relative_to(ROOT / "tmp/delivery-work/installed"), "installed wheel required"
    identity = _manifest_identity(json.loads((package / "_bin/manifest.json").read_text()))
    key = bytes(range(32))
    clients = {False: Client(None, allow_plain=True), True: Client(key)}
    references = {False: module.Redactor(), True: module.Redactor(key=key)}
    rng = random.Random(SEED)
    corpus_raw = (ROOT / pins["corpus_fixture"]).read_bytes()
    if pins["corpus_format"] == "gzip-jsonl":
        corpus_raw = gzip.decompress(corpus_raw)
    assert hashlib.sha256(corpus_raw).hexdigest() == pins["corpus_sha256"]
    corpus_inputs = [row["input"] for line in corpus_raw.splitlines() if line
                     for row in (json.loads(line),)
                     if row["tier"] == "rules" and "input" in row and len(row["input"].encode()) <= TEXT_CAP - 4096]
    assert corpus_inputs
    stream_digest = hashlib.sha256()
    comparisons = 0
    differences = []
    started = time.monotonic()
    try:
        for i in range(CASES):
            if time.monotonic() - started > 1800:
                raise RuntimeError("campaign deadline")
            text = generate(rng, i, corpus_inputs)
            value = {"ordinary": [text, None, i], "nested": {"token": text}}
            stream_digest.update(json.dumps([i, text, value], ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
            for keyed in (False, True):
                for mode, data in (("text", text), ("value", value)):
                    oracle = references[keyed]
                    try:
                        expected = oracle.string(data) if mode == "text" else oracle.json_value(data)
                    except module.RedactDepthError:
                        expected = "core_failure"
                    try:
                        actual = clients[keyed].string(data) if mode == "text" else clients[keyed].value(data)
                    except CaviarError as exc:
                        actual = exc.code
                    comparisons += 1
                    if actual != expected:
                        differences.append({"id": i, "mode": mode, "keyed": keyed})
                        # One bounded synthetic reproducer, private by default.
                        output.with_suffix(".repro.json").write_text(json.dumps({"id": i, "text": text, "value": value}))
                        raise RuntimeError("differential mismatch")
            if (i + 1) % 1000 == 0:
                print("Differential cases:", i + 1, flush=True)
    finally:
        for client in clients.values():
            client.close()
        result = {"seed": SEED, "cases": comparisons // 4, "comparisons": comparisons,
                  "differences": differences, "input_sha256": stream_digest.hexdigest(),
                  "identity": identity, "reference_sha256": pins["reference_sha256"],
                  "binding_path": str(package), "text_cap": TEXT_CAP, "tree_depth_cap": 32,
                  "artifact_hashes": {name: hashlib.sha256((package / name).read_bytes()).hexdigest()
                      for name in ("client.py", "__init__.py", "_bin/manifest.json", "_bin/caviar-redact-worker")}}
        output.write_text(json.dumps(result, indent=2) + "\n")
    assert comparisons == CASES * 4 and not differences


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    run(args.output, args.reference)
