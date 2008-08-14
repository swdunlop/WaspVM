(import "lib/test")
(import "mosref/drone")
(import "mosref/console")
(import "lib/fuzz-filter")

(define (wait/doom . rest)
  (define doom (make-channel))
  (define time (timeout 5000 doom 
                  '(fail "Failed to complete tests in the allotted time")))
  (define data (error-on-fail (wait @rest doom)))
  (cancel-timeout time)
  data)

(define (expect channel value)
  (equal? value (wait/doom channel)))

(enable-spot-tests)

(define console-ecdh (make-ecdh-key 384))
(define drone-port #f)
(define console-port #f)

(define drone-xmit (make-channel))
(define console-xmit (make-channel))
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

(define sync (make-channel))
(spawn (lambda ()
         (set! drone-port (drone-affiliation console-ecdh 
                                             drone-xmit drone-recv))
         (send 'drone-ready sync)))

(spawn (lambda ()
         (set! console-port (console-affiliation console-ecdh 
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

(define (fuzz xmit recv ct)
  (until (<= ct 0)
     (set! ct (- ct 1))
     (define msg (random-string (random-integer 0 1024)))
     (send (copy-string msg) xmit)
     (print (if (string=? (wait/doom recv) msg) "." "x")))
  (print *line-sep*))

(fuzz console-xmit drone-recv 1000)
(fuzz drone-xmit console-recv 1000)

(send 'close console-xmit)
(s: (wait/doom drone-recv))
(r: 'close)

(send 'close drone-xmit)
(s: (wait/doom console-recv))
(r: 'close)

