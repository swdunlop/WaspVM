; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "mosref/base")

(import "lib/crypto-filter")
(import "lib/checksum-filter")
(import "lib/collate-filter")
(import "lib/copy-filter")
(import "lib/trace")
(import "lib/with-io")
(import "mosref/patch")

(export make-iv make-private-key decrypt encrypt
        find-public-key find-shared-secret)

(define (encrypt keystr plaintext)
  (salsa20-encrypt (make-salsa20-key keystr) plaintext))

(define (decrypt keystr plaintext)
  (salsa20-decrypt (make-salsa20-key keystr) plaintext))

;;; We trust the PRNG for our IV's..
(define (make-iv) (read-prng 8))

;;; But the node key? Let's aim higher..  Oh Mr. OS...
;(define (make-private-key) (read-entropy 32))
(print "TODO: Use Entropy for Node Keys again..\n")
(define (make-private-key) (read-prng 32))

(define find-public-key curve25519-public)
(define find-shared-secret curve25519-secret)

(export make-mosref-recv make-mosref-xmit)

(define (make-mosref-xmit xmit xmit-key xmit-iv)
  (define xmit-key (make-salsa20-key xmit-key xmit-iv))
  (define (xmit-encrypt message) (salsa20-encrypt xmit-key message))

  (output-chain xmit
                ;(trace-filter "xmit-ciphertext")
                (encrypt-filter xmit-encrypt)
                ;(trace-filter "xmit-plaintext w/len+cs")
                (prepend-collation-filter)
                ;(trace-filter "xmit-plaintext w/cs")
                (prepend-checksum-filter crc32)
                ;(trace-filter "xmit-plaintext")
                (copy-filter)))

(define (make-mosref-recv extra recv recv-key recv-iv)
  (define recv-key (make-salsa20-key recv-key recv-iv))
  (define (recv-decrypt message) (salsa20-decrypt recv-key message))
    
  (when extra
    (set! recv (preface-input extra recv)))

  (input-chain recv
               (halt-on-close)
               ;(trace-filter "recv-ciphertext")
               (decrypt-filter recv-decrypt)
               ;(trace-filter "recv-plaintext w/len+cs")
               (check-collation-filter)
               ;(trace-filter "recv-plaintext w/cs")
               (check-checksum-filter crc32)
               ;(trace-filter "recv-plaintext")
               ))

(define (spawn-endpoint endpoint break xmit recv)
  ;(set! xmit (output-chain xmit (trace-filter "XMIT")))
  ;(set! recv (input-chain  recv (trace-filter "RECV")))
  (define bridge (make-bridge xmit recv))
  (define lanes (bridge-lanes bridge))

  (define (spawn-endpoint/lane lane)
    (when (eq? lane 'close)
      (break bridge)
      (halt))

    (spawn (lambda ()
             (with-input (lane-recv lane)
               (with-output (lane-xmit lane)
                 (endpoint bridge))))))

  (spawn (lambda ()
           (forever
             (spawn-endpoint/lane (wait lanes)))))
  
  bridge)

(export spawn-endpoint)
