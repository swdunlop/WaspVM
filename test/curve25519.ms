(import "lib/test")

(enable-spot-tests)

(define (spam item) #f)
(define (spam* . items)
  (for-each spam items)
  (spam *line-sep*))

(define private-1 
        "a\1\2\3\4\5\6\7\8\9\0\1\2\3\4\5\6\7\8\9\0\1\2\3\4\5\6\7\8\9\0a")
(define private-2 
        "a\1\2\3\4\5\6\7\8\9\0\1\2\3\4\5\6\7\8\9\0\1\2\3\4\5\6\7\8\9\0b")

(define public-1 (curve25519-public private-1))
(define public-2 (curve25519-public private-2))

(s: public-1)
(t: (= (string-length _) 32))

(s: public-2)
(t: (= (string-length _) 32))

(define secret-1 (curve25519-secret private-1 public-2))
(define secret-2 (curve25519-secret private-2 public-1))

(spam* " SECRET 1: "  (format secret-1))
(spam* " SECRET 2: "  (format secret-2))

(s: secret-1)
(t: (= (string-length _) 32))
(t: (string=? secret-1 secret-2))

