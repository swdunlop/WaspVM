(import "lib/test")
(import "mosref/base")

(enable-spot-tests)

(print "Gathering entropy..\n")

(define private-1  (make-private-key))
(define private-2  (make-private-key))

(define public-1   (find-public-key private-1))
(define public-2   (find-public-key private-2))

(define secret-1 (find-shared-secret private-1 public-2))
(define secret-2 (find-shared-secret private-2 public-1))

(s: secret-1)
(r: secret-2)

(define iv-1  (make-iv))
(define iv-2  iv-1)

(print "..Entropy gathered, proceeding to test.\n")

(define transport (make-queue))

(define xmit (make-mosref-xmit transport secret-1 iv-1))
(define recv (make-mosref-recv transport secret-2 iv-2))

;; Shameless Pirates of Penzance fandom follows:
(define verse
  (string-join " " 
               "I am the very model of a modern Major-General,"
               "I've information vegetable, animal, and mineral,"
               "I know the kings of England, and I quote the fights historical"
               "From Marathon to Waterloo, in order categorical;"
               "I'm very well acquainted, too, with matters mathematical,"
               "I understand equations, both the simple and quadratical,"
               "About binomial theorem I'm teeming with a lot o' news,"
               "With many cheerful facts about the square of the hypotenuse."))

(s: (send "Hello" xmit)
    (wait 1000 recv))

(r: "Hello")

(s: (send verse xmit)
    (wait 1000 recv))

(r: verse)

