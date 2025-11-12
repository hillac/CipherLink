# CipherLink - Self contained data url based secret sharing tool

## Overview

This tool lets you share secret with a password or key exchange with zero infrastructure and only requires a browser. It doesnt even require a network connection. It is not audited, and just for fun, I make no guarentees on security and take no responsibility anything you do with it.

The goal was to make this small and simple so it's easy to scan and audit the code yourself without trusting a huge codebase or complicated build tooling.

## How to use

Build it by running build.py. Or use the build output url at the end of this section. Always build the url yourself or get it from this readme.

## Key exchange
Input your secret message, and generate a shareable url (it will be big). Send that url to the recipient. Then, on a different channel, they will reply with some data (a public key). Eg, send the data url by email, and  they should reply on whatsapp. If they reply by the same channel you sent the url on, ignore the data and request they use a different channel. This is to authenticate them.

## Password
Input your secret message, and a password and generate a shareable url (it will be big). Send that url to the recipient. Then, on a different channel, send the password. Eg, send the data url by email, and password on whatsapp, set to disappear.

## URLs
Copy this url into your browser bar to use the tool:
Password tool:
```url
__ENCODE_URL_PASSWORD__
```
Key Exchange tool:
```url
__ENCODE_URL_KEY_EXCHANGE__
```

## Implemenation Notes

- Crypto was all self implemented in js, because there's no crypto.subtle in the data url context in browsers. I could have used an audited implementation, but this is for fun. Theres is a small test script that does a few simple sanity checks. To keep the sharable link small I would need to strip out just the code I need from an audited implementation. Or I could try build a minimal wasm package using a c or rust implementation.
- I wanted to try data url to see if this would work. An alternative would have been making an html file. That would still be pretty easy to share, and crypto.subtle is available when you open a local html file, so no js crypto needed. Since it would be sent as a file rather than cumbersome text, I could embed a much larger secret, like entire files. I might try it later if this project gets any interest.
- It would be cool to write this as a quine, so someone who receives a message could then send their own message. But it's better to link them to somewhere to get the trusted intitial data url.

## Key exchange
A random key `messageKey` is generated to encrypt the sender's message `m` into ciphertext `ct` with aes-256 gcm. A x25519 keypair is then generated `privA` and `pubA` as well as a salt `s`. `s`, `pubA`, `ct` are sent to the recipient. The recipient generates their own x25519 keypair `privB` and `pubB`, and send `pubB` to the sender. The sender derives the `sharedSecret` and uses the salt and hkdf to get the `sharedKey`, then uses aes-256 gcm to encrypt `messageKey` with `sharedKey` to make `messageKeyEncrypted`. They send `messageKeyEncrypted` to the recipient. The recipient also generates `sharedKey` and decryts `messageKeyEncrypted` to get `messageKey` then decrypts the `ct` to get `m`.

- This schema allows the secret payload to be in the data url. Using 2 channels in necessary since a mitm could simply change the recipients public key for their own.
- I'm unsure if the salt should be sent in the first step, or second.
- I need some form of authentication. Given the inital sending of the data url should happen over a different chanel, I can send a secret that can be used to authenticate the key exchange. It will provide warnings if something is wrong. This is a todo. Without this, if the sender responds to a mitm on the second channel, the mitm could then attempt to get `ct` at a later date and find `m`.


## Password
It uses 500k iters of pbkdf2 on the password. It then uses aes-256 gcm to encrypt the message.

- There's no point sending the url and password over the same channel. You're sending plain text at that point.
- I used pbkdf2 even though it's old as that's whats in subtle, and it's way easier than argon2 to make.

## Build
- The script is in python so no one needs to stuff around with npm. I wanted to avoid requiring installs. The crypto test file requires node to run it (or maybe just a browser console).
- The weird moduling system is so it's easy to build with just python, and so I can avoid the same script appearing in encode and decode templates. The tag lets me copy the code and saves space in the encode url. It was a quick hack, might be better as a iife module not sure.