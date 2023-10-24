# argon2id

Provide an API for handling argon2id password hashes.

argon2id provides a wrapper around golang.org/x/crypto/argon2 suitable for generating and checking passwords.
Only the argon2id algorithm is supported.

GenerateFromPassword() will successfully generate a password hash using default values if any of
`time`, `mem`, or `threads` are out of bounds; however, err != nil.

