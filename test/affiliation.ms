(import "lib/test")

(import "mosref/transport")
(import "mosref/drone")
(import "mosref/console")
(import "lib/fuzz-filter")

; Seed PRNG in case we're scarce on entropy.
(random-integer 1 100)

(define (wait/doom src) (wait src))
;(define (wait/doom src)
;  (define data (wait 1000 src))
; (when (eq? data 'timeout)
;   (error 'fail "Failed to complete tests in the allotted time"))
; (return data))

(define (expect channel value)
  (equal? value (wait/doom channel)))

(enable-spot-tests)

(define console-private (make-private-key))
(define console-public (find-public-key console-private))
(define drone-port #f)
(define console-port #f)

(define drone-xmit (make-queue))
(define console-xmit (make-queue))
(define drone-recv (input-chain console-xmit 
                                ;(trace-filter "drone-recv")
                                (fuzz-filter) 
                                ;(trace-filter "drone-recv/fz")
                                ))

(define console-recv (input-chain drone-xmit 
                                  ;(trace-filter "console-recv")
                                  (fuzz-filter) 
                                  ;(trace-filter "console-recv/fz")
                                  ))

(define sync (make-queue))
(spawn (lambda ()
         (set! drone-port (drone-affiliation console-public
                                             drone-xmit drone-recv))
         (send 'drone-ready sync)))

(spawn (lambda ()
         (set! console-port (console-affiliation console-private
                                                 console-xmit console-recv))
         (send 'console-ready sync)))

(wait/doom sync)
(wait/doom sync)

(define drone-xmit (car drone-port))
(define drone-recv (cadr drone-port))

(define console-xmit (car console-port))
(define console-recv (cadr console-port))

(define m1 "alpha")
(define m2 "now is the time for all good people")
(define m3 "")

(define mm1 (copy-string m1))
(define mm2 (copy-string m2))
(define mm3 (copy-string m3))

(send m1 console-xmit)
(s: (wait/doom drone-recv))
(r: m1)
(r: mm1)

(send m2 console-xmit)
(s: (wait/doom drone-recv))
(r: m2)
(r: mm2)

(send m3 console-xmit)
(s: (wait/doom drone-recv))
(r: m3)
(r: mm3)

(send m1 console-xmit)
(send m2 console-xmit)
(send m3 console-xmit)

(s: (wait/doom drone-recv))
(r: m1)
(r: mm1)

(s: (wait/doom drone-recv))
(r: m2)
(r: mm2)

(s: (wait/doom drone-recv))
(r: m3)
(r: mm3)

(send m1 drone-xmit)
(s: (wait/doom console-recv))
(r: m1)
(r: mm1)

(send m2 drone-xmit)
(s: (wait/doom console-recv))
(r: m2)
(r: mm2)

(send m3 drone-xmit)
(s: (wait/doom console-recv))
(r: m3)
(r: mm3)

(send m1 drone-xmit)
(send m2 drone-xmit)
(send m3 drone-xmit)

(s: (wait/doom console-recv))
(r: m1)
(r: mm1)

(s: (wait/doom console-recv))
(r: m2)
(r: mm2)

(s: (wait/doom console-recv))
(r: m3)
(r: mm3)

(send m1 drone-xmit)
(send m2 drone-xmit)
(send m3 drone-xmit)

(s: (wait/doom console-recv))
(r: m1)
(r: mm1)
(s: (wait/doom console-recv))
(r: m2)
(r: mm2)
(s: (wait/doom console-recv))
(r: m3)
(r: mm3)

(send m1 console-xmit)
(s: (wait/doom drone-recv))
(r: m1)
(r: mm1)

(send m2 console-xmit)
(s: (wait/doom drone-recv))
(r: m2)
(r: mm2)

(send m3 console-xmit)
(s: (wait/doom drone-recv))
(r: m3)
(r: mm3)
(exit)
(define (fuzz xmit recv ct)
  (until (<= ct 0)
     (set! ct (- ct 1))
     (define msg (read-prng (random-integer 0 4096)))
     (send (copy-string msg) xmit)
     (print (if (string=? (wait/doom recv) msg) "." "x")))
  (print *line-sep*))

(fuzz console-xmit drone-recv 10000)
(fuzz drone-xmit console-recv 10000)

(send 'close console-xmit)
(s: (wait/doom drone-recv))
(r: 'close)

(send 'close drone-xmit)
(s: (wait/doom console-recv))
(r: 'close)

