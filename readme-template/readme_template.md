# CipherLink - Self contained data url based secret sharing tool

## Overview

This tool lets you share secret with a password or key with zero infrastructure and only requires a browser. It doesnt even require a network connection. It is not audited, and just for fun, I make no guarentees on security and take no responsibility anything you do with it.

## How to use

Build it by running build.py. Or use the build output url at the end of this readme. Input your secret message, and a password and generate a shareable url (it will be big). Send that url to the recipient. Then, on a different channel, send the password. Eg, send the data url by email, and password on whatsapp, set to disappear. Always build the url yourself or get it from this readme.

## Security Notes

- Crypto was all re-implemented in js, because there's no crypto.subtle in the data url context in browsers. Yes, I could have used an audited implementation, but this is for fun. Theres is a small test script that does a few simple sanity checks.
- There's no point sending the url and password over the same channel. You're sending plain text at that point.
- It would be cool to write this as a quine, so someone who receives a message could then send their own message. But it's better to link them to somewhere to get the trusted intitial data url.

# URL
Copy this url into your browser bar to use the tool:
Password tool:
```url
__ENCODE_URL_PASSWORD__
```
Key Exchange tool:
```url
__ENCODE_URL_KEY_EXCHANGE__
```