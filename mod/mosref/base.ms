; Copyright (C) 2006, Ephemeral Security, LLC
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
(import "lib/cfb")
(import "lib/block-filter")
(import "lib/checksum-filter")
(import "lib/copy-filter")
;(import "lib/trace")

(export *sprng* *ecdh-keysize* *sig-length* make-iv)

(define *sprng* (make-random "sprng"))
(define *ecdh-keysize* 384)
(define *sig-length* 16)

(define (make-iv)
  (random-string 16 *sprng*))

(define (make-mosref-xmit xmit xmit-key xmit-iv)
  (define xmit-block-size (key-block-size xmit-key))
  (define xmit-cfb (make-cfb xmit-key xmit-iv aes-encrypt))
  (define (xmit-encrypt block)
    (cfb-encrypt xmit-cfb block))

  (output-chain xmit
                ;(trace-filter "xmit-ciphertext-block")
                (encrypt-filter xmit-encrypt)
                ;(trace-filter "xmit-plaintext-block")
                (block-split-filter xmit-block-size)
                ;(trace-filter "xmit-plaintext w/cs")
                (prepend-checksum-filter crc32)
                ;(trace-filter "xmit-plaintext")
                (copy-filter)))

(define (make-mosref-recv recv recv-key recv-iv)
  (define recv-block-size (key-block-size recv-key))
  (define recv-cfb (make-cfb recv-key recv-iv aes-encrypt))
  (define (recv-decrypt block) (cfb-decrypt recv-cfb block))

  (input-chain recv
               ;(trace-filter "recv-ciphertext-data")
               (fragment-filter recv-block-size)
               ;(trace-filter "recv-ciphertext-block")
               (decrypt-filter recv-decrypt)
               ;(trace-filter "recv-plaintext-block")
               (block-merge-filter recv-block-size)
               ;(trace-filter "recv-plaintext w/cs")
               (check-checksum-filter crc32)
               ;(trace-filter "recv-plaintext")
               ))

(export make-mosref-recv make-mosref-xmit)

