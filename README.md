# Sousveillance - a reverse-engineering CTF challenge

This is the source code for a capture-the-flag challenge that tests the player's ability reverse-engineer a Linux x86-64 binary executable.

### Build instructions

1. Install `automake` and `autoconf`.
2. Run `autoreconf -s -i` in the source directory.
3. Use the `configure` script as usual.
4. The final result is a binary executable named `ptooie`. This is the only file that the player needs to have.

### Solving the challenge

You should run `ptooie`, fulfil its requirement and you will get the flag.

You can check the source code to make sure that `ptooie` does not do anything malicious. Unfortunately, the source code also contains spoilers. It's your call.

The only way to validate a flag is to send it to the author of the challenge (gbr@voidland.org). I will manually check the flag and I will respond with the points you have earned. Do not assume that if something looks like a flag then it would give you the points.
