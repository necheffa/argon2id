/*
   Copyright (C) 2023 Alexander Necheff

   This file is part of argon2id.

   argon2id is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, at version 3 of the License.

   argon2id is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with argon2id.  If not, see <https://www.gnu.org/licenses/>.
*/

package argon2id

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	// TODO: validate these are the recommended defaults
	DefaultTime    uint32 = 8
	DefaultMem     uint32 = 8
	DefaultThreads uint8  = 4
	DefaultKeyLen  uint32 = 32

	Prefix string = "an99"

	seporator byte   = '$'
	saltLen   int    = 16 // per RFC 9106 recommendations.
	keyLen    uint32 = 32 // TODO: follow up on this, but this should be a 256 bit key (a.k.a. 32 bytes)
)

var (
	ErrMismatchedHashAndPassword = errMismatchedHashAndPassword()
	ErrUnexpectedSaltSize        = errUnexpectedSaltSize()
	ErrInvalidTimeParm           = errInvalidTimeParm()
	ErrInvalidMemParm            = errInvalidMemParm()
	ErrInvalidThreadParm         = errInvalidThreadParm()
	ErrInvalidHashSigil          = errInvalidHashSigil()
)

func errMismatchedHashAndPassword() error {
	return errors.New("necheff.net/argon2id: hashedPassword is not the hash of the given password")
}

func errUnexpectedSaltSize() error {
	return errors.New("necheff.net/argon2id: number of bytes read for salt was not " + fmt.Sprint(saltLen))
}

func errInvalidTimeParm() error {
	return errors.New("necheff.net/argon2id: invalid time paramater")
}

func errInvalidMemParm() error {
	return errors.New("necheff.net/argon2id: invalid memory paramater")
}

func errInvalidThreadParm() error {
	return errors.New("necheff.net/argon2id: invalid threads paramater")
}

func errInvalidHashSigil() error {
	return errors.New("necheff.net/argon2id: invalid hash sigil")
}

func GenerateFromPassword(password []byte, time, mem uint32, threads uint8) ([]byte, error) {
	saltBuf := make([]byte, saltLen, saltLen)
	n, err := rand.Read(saltBuf)
	if err != nil {
		return nil, err
	}
	if n != saltLen {
		return nil, ErrUnexpectedSaltSize
	}

	// TODO: set maximum password check to avoid collisions based on key length.

	if time == 0 {
		time = DefaultTime
	}

	if mem == 0 {
		mem = DefaultMem
	}

	if threads == 0 {
		threads = DefaultThreads
	}

	hashBuf := argon2.IDKey(password, saltBuf, time, mem, threads, keyLen)
	hash := make([]byte, base64.StdEncoding.EncodedLen(len(hashBuf)))
	defer eraseBuf(hash)
	base64.StdEncoding.Encode(hash, hashBuf)

	salt := make([]byte, base64.StdEncoding.EncodedLen(len(saltBuf)))
	defer eraseBuf(salt)
	base64.StdEncoding.Encode(salt, saltBuf)

	sep := []byte{seporator}
	timeStr := fmt.Sprint(time)
	memStr := fmt.Sprint(mem)
	threadsStr := fmt.Sprint(threads)

	// preallocate the crypt buffer to avoid transparent reallocation leaving dereferenced fragments in memory.
	// this allows callers to securly wipe memory in multitenant environments.
	size := len([]byte(Prefix)) + len(sep) + len(timeStr) + len(sep) + len(memStr) + len(sep) + len(threadsStr) + len(sep) +
		len(salt) + len(sep) + len(hash)
	crypt := make([]byte, 0, size)

	crypt = append(crypt, []byte(Prefix)...)
	crypt = append(crypt, sep...)
	crypt = append(crypt, fmt.Sprint(time)...)
	crypt = append(crypt, sep...)
	crypt = append(crypt, fmt.Sprint(mem)...)
	crypt = append(crypt, sep...)
	crypt = append(crypt, fmt.Sprint(threads)...)
	crypt = append(crypt, sep...)
	crypt = append(crypt, salt...)
	crypt = append(crypt, sep...)
	crypt = append(crypt, hash...)

	return crypt, nil
}

func CompareHashAndPassword(hashedPassword, password []byte) error {
	parms := bytes.Split(hashedPassword, []byte{seporator})

	if !bytes.Equal(parms[0], []byte(Prefix)) {
		return ErrInvalidHashSigil
	}

	timeStr := parms[1]
	memStr := parms[2]
	threadStr := parms[3]
	saltEnc := parms[4]
	hashEnc := parms[5]

	time, err := strconv.ParseUint(string(timeStr), 10, 32)
	if err != nil {
		// TODO: how to wrap `err` in this?
		return ErrInvalidTimeParm
	}

	mem, err := strconv.ParseUint(string(memStr), 10, 32)
	if err != nil {
		return ErrInvalidMemParm
	}

	threads, err := strconv.ParseUint(string(threadStr), 10, 8)
	if err != nil {
		return ErrInvalidThreadParm
	}

	salt := make([]byte, base64.StdEncoding.DecodedLen(len(saltEnc)))
	defer eraseBuf(salt)
	saltLen, err := base64.StdEncoding.Decode(salt, saltEnc)
	if err != nil {
		return err
	}

	hash := make([]byte, base64.StdEncoding.DecodedLen(len(hashEnc)))
	defer eraseBuf(hash)
	hashLen, err := base64.StdEncoding.Decode(hash, hashEnc)
	if err != nil {
		return err
	}

	compHash := argon2.IDKey(password, salt[:saltLen], uint32(time), uint32(mem), uint8(threads), keyLen)

	if bytes.Equal(hash[:hashLen], compHash) {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

// eraseBuf fills len(buf) with space characters.
// if buf is nil or zero length, eraseBuf takes no action.
func eraseBuf(buf []byte) {
	for i := 0; i < len(buf); i++ {
		buf[i] = ' '
	}
}
