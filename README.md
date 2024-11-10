# argon2id

Provide an API for handling argon2id password hashes.

argon2id provides a wrapper around golang.org/x/crypto/argon2 suitable for generating and checking passwords.
Only the argon2id algorithm is supported.

GenerateFromPassword() will successfully generate a password hash using default values if any of
`time`, `mem`, or `threads` are out of bounds; however, err != nil.

## Licensing

argon2id is distributed under the terms of the LGPLv3, refer to the COPYING and COPYING.LESSER files for
the complete terms of the license.
