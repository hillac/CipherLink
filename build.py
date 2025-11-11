#!/usr/bin/env python3
import base64
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "src"
DECODE = SRC / "simple_password" / "decode_template.html"
ENCODE = SRC / "simple_password" / "encode_template.html"
OUT = HERE / "generated_final.html"
AES256GCM_JS = SRC / "crypto" / "aes256gcm.js"
PBKDF2_JS = SRC / "crypto" / "PBKDF2.js"
README_TEMPLATE = HERE / "readme-template" / "readme_template.md"

def strip_js_comments(js: str) -> str:
    js = re.sub(r"//.*?$", "", js, flags=re.MULTILINE)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)
    js = re.sub(r"\n\s*\n\s*\n+", "\n\n", js)
    return js

def main():
    decode_html = DECODE.read_text(encoding="utf-8")
    encode_html = ENCODE.read_text(encoding="utf-8")

    output_html = encode_html.replace("__DECODE_HTML__", decode_html)

    aes256gcm_js = strip_js_comments((AES256GCM_JS).read_text(encoding="utf-8"))
    output_html = output_html.replace("__INCLUDE_AES256GCM_JS__", aes256gcm_js)

    pbkdf2_js = strip_js_comments((PBKDF2_JS).read_text(encoding="utf-8"))
    output_html = output_html.replace("__INCLUDE_PBKDF2_JS__", pbkdf2_js)

    OUT.write_text(output_html, encoding="utf-8")

    b64 = base64.b64encode(output_html.encode("utf-8")).decode("ascii")

    readme = README_TEMPLATE.read_text(encoding="utf-8")
    readme = readme.replace("__ENCODE_URL__", f"data:text/html;base64,{b64}")
    (HERE / "README.md").write_text(readme, encoding="utf-8")

    print(f"data:text/html;base64,{b64}")

if __name__ == "__main__":
    main()
