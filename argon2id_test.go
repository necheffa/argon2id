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
