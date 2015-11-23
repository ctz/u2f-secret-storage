Key 'storage' by abusing U2F devices
====================================

This is a proof of concept for abusing U2F devices
and the cryptography they use to derive a stable secret.

If you're brave or reckless, you could use this technique to derive keys
to encrypt your disk, or password database, or SSH keys.

See https://jbp.io/2015/11/23/abusing-u2f-to-store-keys/ for the background.

Usage
-----

You need python-u2flib-host first: https://github.com/Yubico/python-u2flib-host

Then run `python u2fkey.py enroll` to set things up.  This will print the key
value and store state to `data.json` in the working directory.

Next, run `python u2fkey.py auth` to get the key value back.

License
-------
CC0
