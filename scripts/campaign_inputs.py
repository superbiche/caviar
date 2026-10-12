# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Unchanged deterministic corpus and fuzz materialization shared by oracle runners."""
import json
TEXT_CAP = 65536

def materialize(seed):
    if "input" in seed:
        return seed["input"]
    generator = seed["generator"]
    body = generator["unit"] * generator["count"]
    if generator["kind"] == "repeat":
        return generator.get("prefix", "") + body + generator.get("suffix", "")
    if generator["kind"] == "json-string":
        return '{"' + generator["key"] + '":"' + body + '"}'
    raise SystemExit("Unsupported corpus generator")


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
