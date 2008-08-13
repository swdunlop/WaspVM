(import "lib/test")

(enable-spot-tests)

;; Shameless Pirates of Penzance fandom follows:
(define plaintext 
  (string-join " " "I am the very model of a modern Major-General,"
                   "I've information vegetable, animal, and mineral,"
                   "I know the kings of England, and I quote the fights historical"
                   "From Marathon to Waterloo, in order categorical;"
                   "I'm very well acquainted, too, with matters mathematical,"
                   "I understand equations, both the simple and quadratical,"
                   "About binomial theorem I'm teeming with a lot o' news,"
                   "With many cheerful facts about the square of the hypotenuse."))

(define seed (read-prng 32))
(define xmit-key  (make-salsa20-key seed))
(define recv-key  (make-salsa20-key seed))

(define ciphertext-1 (salsa20-encrypt xmit-key plaintext))

(s: ciphertext-1)
(t: (= (string-length _) (string-length plaintext)))
(t: (not (string=? ciphertext-1 plaintext)))

(define intercept (salsa20-decrypt recv-key ciphertext-1))
(s: intercept)
(t: (string=? intercept plaintext))

(define iv   (read-prng 8))
(define ciphertext-2 (salsa20-encrypt xmit-key plaintext iv))

(s: ciphertext-2)
(t: (= (string-length _) (string-length plaintext)))
(t: (not (string=? ciphertext-2 plaintext)))

;;TODO: Note, there is a 1 in 2 ^ 64 chance of this test failing without cause.
;;      Let me know if you win that lottery..

(t: (not (string=? ciphertext-1 ciphertext-2)))

(define intercept (salsa20-decrypt recv-key ciphertext-2 iv))
(s: intercept)
(t: (string=? intercept plaintext))

