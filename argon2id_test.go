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

package argon2id_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"necheff.net/argon2id"

	"errors"
)

var _ = Describe("Argon2id", func() {

	Describe("CompareHashAndPassword", func() {
		Context("with a valid password", func() {
			It("should not return an error", func() {
				hash, err := argon2id.GenerateFromPassword([]byte("password"), 4, 12*1024, 6)
				Expect(err).To(BeNil())

				err = argon2id.CompareHashAndPassword(hash, []byte("password"))
				Expect(err).To(BeNil())
			})
		})

		Context("with an invalid password", func() {
			It("should return an ErrMismatchedHashAndPassword error", func() {
				hash, err := argon2id.GenerateFromPassword([]byte("password"), 4, 12*1024, 6)
				Expect(err).To(BeNil())

				err = argon2id.CompareHashAndPassword(hash, []byte("notpassword"))
				Expect(errors.Is(err, argon2id.ErrMismatchedHashAndPassword)).To(BeTrue())
			})
		})
	})
})
