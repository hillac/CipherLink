#!/usr/bin/env python3
import base64
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "src"
DECODE_PASSWORD = SRC / "simple_password" / "decode_template.html"
ENCODE_PASSWORD = SRC / "simple_password" / "encode_template.html"
DECODE_KEY_EXCHANGE = SRC / "key_exchange" / "decode_template_key_exchange.html"
ENCODE_KEY_EXCHANGE = SRC / "key_exchange" / "encode_template_key_exchange.html"

README_TEMPLATE = HERE / "readme-template" / "readme_template.md"

# LIBS
AES256GCM_JS = SRC / "crypto" / "aes256gcm.js"
PBKDF2_JS = SRC / "crypto" / "PBKDF2.js"
X25519_JS = SRC / "crypto" / "x25519.js"


def strip_js_comments(js: str) -> str:
    js = re.sub(r"//.*?$", "", js, flags=re.MULTILINE)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)
    js = re.sub(r"\n\s*\n\s*\n+", "\n\n", js)
    return js

def build(DECODE: pathlib.Path, ENCODE: pathlib.Path):
    decode_html = DECODE.read_text(encoding="utf-8")
    encode_html = ENCODE.read_text(encoding="utf-8")

    output_html = encode_html.replace("__DECODE_HTML__", decode_html)

    aes256gcm_js = strip_js_comments((AES256GCM_JS).read_text(encoding="utf-8"))
    output_html = output_html.replace("__INCLUDE_AES256GCM_JS__", aes256gcm_js)

    pbkdf2_js = strip_js_comments((PBKDF2_JS).read_text(encoding="utf-8"))
    output_html = output_html.replace("__INCLUDE_PBKDF2_JS__", pbkdf2_js)

    x25519_js = strip_js_comments((X25519_JS).read_text(encoding="utf-8"))
    output_html = output_html.replace("__INCLUDE_X25519_JS__", x25519_js)

    b64 = base64.b64encode(output_html.encode("utf-8")).decode("ascii")

    dataUrl = f"data:text/html;base64,{b64}"
    return dataUrl

def main():
    encode_url_password = build( DECODE_PASSWORD, ENCODE_PASSWORD)
    encode_url_key_exchange = build( DECODE_KEY_EXCHANGE, ENCODE_KEY_EXCHANGE)

    print(encode_url_key_exchange)

    readme_template = README_TEMPLATE.read_text(encoding="utf-8")
    readme_output = readme_template.replace("__ENCODE_URL_PASSWORD__", encode_url_password)
    readme_output = readme_output.replace("__ENCODE_URL_KEY_EXCHANGE__", encode_url_key_exchange)

    output_readme = HERE / "README.md"
    # output_readme.write_text(readme_output, encoding="utf-8")

if __name__ == "__main__":
    main()
