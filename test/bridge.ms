(import "lib/test")
(import "lib/bridge")
(import "lib/trace")

(enable-spot-tests)

;TODO: Need to figure this out for the new no-cancel timeouts.
;(define (wait/doom doom)
;  (define time (timeout 5000 doom 
;                  '(fail "Failed to complete tests in the allotted time")))
;  (define data (error-on-fail (wait doom)))
;  (cancel-timeout time)
;  data)

(define (expect channel value)
  (equal? value (wait channel)))

(define west-to-east (make-queue))
(define east-to-west (make-queue))

(define west-bridge (make-bridge west-to-east east-to-west))
(define east-bridge (make-bridge east-to-west west-to-east))

;(define west-bridge (make-bridge (output-chain west-to-east 
;                                               (trace-filter "west    "))
;                                 east-to-west))
;(define east-bridge (make-bridge (output-chain east-to-west 
;                                               (trace-filter "    east"))
;                                 west-to-east))
(define west-lanes (bridge-lanes west-bridge))
(define east-lanes (bridge-lanes east-bridge))

(define m1 "")
(define m2 "now is the time for all good people")
(define m3 "alpha")

(define east-side (make-lane east-bridge))
(define es-xmit   (lane-xmit east-side))
(define es-recv   (lane-recv east-side))

(define west-side (wait west-lanes))

(define ws-xmit   (lane-xmit west-side))
(define ws-recv   (lane-recv west-side))

(s: (send m1 es-xmit))
(t: (expect ws-recv m1))

(s: (send m1 ws-xmit))
(t: (expect es-recv m1))

(s: (send m2 es-xmit))
(t: (expect ws-recv m2))

(s: (send m2 ws-xmit))
(t: (expect es-recv m2))

(s: (send m3 es-xmit))
(t: (expect ws-recv m3))

(s: (send m3 ws-xmit))
(t: (expect es-recv m3))

(s: (send 'close ws-xmit))
(t: (expect es-recv 'close))

(s: (send 'close es-xmit))
(t: (expect ws-recv 'close))

(define east-side (make-lane east-bridge))
(define es-xmit   (lane-xmit east-side))
(define es-recv   (lane-recv east-side))

(define west-side (wait west-lanes))

(define ws-xmit   (lane-xmit west-side))
(define ws-recv   (lane-recv west-side))

(s: (send m1 es-xmit))
(t: (expect ws-recv m1))

(s: (send m1 ws-xmit))
(t: (expect es-recv m1))

(s: (send m2 es-xmit))
(t: (expect ws-recv m2))

(s: (send m2 ws-xmit))
(t: (expect es-recv m2))

(s: (send m3 es-xmit))
(t: (expect ws-recv m3))

(s: (send m3 ws-xmit))
(t: (expect es-recv m3))

(s: (send 'close es-xmit))
(t: (expect ws-recv 'close))

(s: (send 'close ws-xmit))
(t: (expect es-recv 'close))

(define west-side (make-lane west-bridge))
(define ws-xmit   (lane-xmit west-side))
(define ws-recv   (lane-recv west-side))

(define east-side (wait east-lanes))
(define es-xmit   (lane-xmit east-side))
(define es-recv   (lane-recv east-side))

(s: (send m1 es-xmit))
(t: (expect ws-recv m1))

(s: (send m1 ws-xmit))
(t: (expect es-recv m1))

(s: (send m2 es-xmit))
(t: (expect ws-recv m2))

(s: (send m2 ws-xmit))
(t: (expect es-recv m2))

(s: (send m3 es-xmit))
(t: (expect ws-recv m3))

(s: (send m3 ws-xmit))
(t: (expect es-recv m3))

(define west-side (make-lane west-bridge))
(define ws-xmit   (lane-xmit west-side))
(define ws-recv   (lane-recv west-side))

(define east-side (wait east-lanes))

(define es-xmit   (lane-xmit east-side))
(define es-recv   (lane-recv east-side))

(s: (send m1 es-xmit))
(t: (expect ws-recv m1))

(s: (send m1 ws-xmit))
(t: (expect es-recv m1))

(s: (send m2 es-xmit))
(t: (expect ws-recv m2))

(s: (send m2 ws-xmit))
(t: (expect es-recv m2))

(s: (send m3 es-xmit))
(t: (expect ws-recv m3))

(s: (send m3 ws-xmit))
(t: (expect es-recv m3))

(define west-side (make-reserved-lane west-bridge))
(define ws-xmit   (lane-xmit west-side))
(define ws-recv   (lane-recv west-side))

(pause)
(pause)
(pause)
(pause)
(pause)
(pause)
(pause)
(pause)
(pause)
(pause)
(print "Done pausing.\n")

(define east-side (find-reserved-lane east-bridge (lane-tag west-side)))

(define es-xmit   (lane-xmit east-side))
(define es-recv   (lane-recv east-side))

(s: (send m1 es-xmit))
(t: (expect ws-recv m1))

(s: (send m1 ws-xmit))
(t: (expect es-recv m1))

(s: (send m2 es-xmit))
(t: (expect ws-recv m2))

(s: (send m2 ws-xmit))
(t: (expect es-recv m2))

(s: (send m3 es-xmit))
(t: (expect ws-recv m3))

(s: (send m3 ws-xmit))
(t: (expect es-recv m3))

