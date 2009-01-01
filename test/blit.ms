(import "lib/iterate")
(import "lib/scud")
(scud-cls)

(define t "0123456789ABCDEF")
(define f (make-string 16 0))
(for-each (lambda (col)
            (string-set! f col col))
          (integer-range 0 16))

(for-each (lambda (row)
            (define b (make-string 16 row))
            (console-blit t f b)
            (print *line-sep*))
          (integer-range 0 8))

(set-scud-colors 'clear 'white)
