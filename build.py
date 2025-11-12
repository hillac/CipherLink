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
HMAC_JS = SRC / "crypto" / "hmac.js"
HKDF_JS = SRC / "crypto" / "hkdf.js"
X25519_JS = SRC / "crypto" / "x25519.js"


def strip_js_comments(js: str) -> str:
    js = re.sub(r"//.*?$", "", js, flags=re.MULTILINE)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)
    js = re.sub(r"\n\s*\n\s*\n+", "\n\n", js)
    return js

def inject_js(input_html: str, placeholder: str, js_path: pathlib.Path) -> str:
    js_content = strip_js_comments(js_path.read_text(encoding="utf-8"))
    return input_html.replace(placeholder, js_content)

def build(DECODE: pathlib.Path, ENCODE: pathlib.Path):
    decode_html = DECODE.read_text(encoding="utf-8")
    encode_html = ENCODE.read_text(encoding="utf-8")

    output_html = encode_html.replace("__DECODE_HTML__", decode_html)

    output_html = inject_js(output_html, "__INCLUDE_AES256GCM_JS__", AES256GCM_JS)
    output_html = inject_js(output_html, "__INCLUDE_HMAC_JS__", HMAC_JS)
    output_html = inject_js(output_html, "__INCLUDE_HKDF_JS__", HKDF_JS)
    output_html = inject_js(output_html, "__INCLUDE_PBKDF2_JS__", PBKDF2_JS)
    output_html = inject_js(output_html, "__INCLUDE_X25519_JS__", X25519_JS)

    b64 = base64.b64encode(output_html.encode("utf-8")).decode("ascii")

    dataUrl = f"data:text/html;base64,{b64}"
    return dataUrl

def main():
    encode_url_password = build( DECODE_PASSWORD, ENCODE_PASSWORD)
    encode_url_key_exchange = build( DECODE_KEY_EXCHANGE, ENCODE_KEY_EXCHANGE)

    # python3 ./build.py | xclip -selection clipboard
    # print(encode_url_password)
    # print(encode_url_key_exchange)

    readme_template = README_TEMPLATE.read_text(encoding="utf-8")
    readme_output = readme_template.replace("__ENCODE_URL_PASSWORD__", encode_url_password)
    readme_output = readme_output.replace("__ENCODE_URL_KEY_EXCHANGE__", encode_url_key_exchange)

    output_readme = HERE / "README.md"
    output_readme.write_text(readme_output, encoding="utf-8")

if __name__ == "__main__":
    main()
