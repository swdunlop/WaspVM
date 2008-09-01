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

(import "lib/buffer-input")
(import "lib/bridge")
(import "lib/trace")
(import "lib/with-io")
(import "lib/patch")

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

(define-filter (mosref-decrypt key iv)
  (set! key (make-salsa20-key key iv))             

  (define read-ciphertext (buffer-input in #f out))
  (define (read . args)
    (define data (read-ciphertext @args))
    (unless (string? data) 
      (send data out) 
      (halt))
    (salsa20-decrypt key data))

  (define buffer #f)
  (define req #f)

  (define (read-block)
    (define len (string->byte (read 1)))

    (when (> len req)
      (send '(fail len "final block of message too large") out)
      (halt))

    (define block-crc (string->quad (read 4)))
    (define block (read len))
    
    (unless (= (crc32 block) block-crc)
      (send `(fail crc "garbled message block received") out)
      (halt))

    (set! req (- req (string-length block)))
    (string-append! buffer block))

  (define (read-message)
    (set! buffer (make-string))
    (set! req (string->quad (read 4)))
    (set! message-crc (string->quad (read 4)))
      
    (while (> req 0) (read-block))

    (unless (= message-crc (crc32 buffer))
      (send `(fail crc "garbled message received") out)
      (halt))
      
    (send buffer out))

  (forever (read-message)))

(define-filter (mosref-encrypt key iv)
  (set! key (make-salsa20-key key iv))             
  (define message #f)
  (define message-ofs #f)
  (define message-left #f)

  (define (write item)
    (send (salsa20-encrypt key item) out))

  (define (send-block)
    (define block-sz (random-integer 16 255))
    (when (> block-sz message-left)
      (set! block-sz message-left))
    (define block (substring message message-ofs block-sz))
    (write (byte->string block-sz))
    (write (quad->string (crc32 block)))
    (write block)
    (set! message-ofs (+ message-ofs block-sz))
    (set! message-left (- message-left block-sz)))
 
  (define (send-message)
    (set! message-left (string-length message))
    (set! message-ofs 0)
    (write (quad->string message-left))
    (write (quad->string (crc32 message)))
    (while (> message-left 0) (send-block)))

  (forever
    (set! message (wait in))
    (unless (string? message)
      (send message out)
      (halt))
    (send-message)))

(define (make-mosref-xmit xmit xmit-key xmit-iv)
  (output-chain xmit (mosref-encrypt xmit-key xmit-iv)))

(define (make-mosref-recv extra recv recv-key recv-iv)
  (when extra (set! recv (preface-input extra recv)))
  (input-chain recv (mosref-decrypt recv-key recv-iv)))

(define (spawn-endpoint endpoint break xmit recv)
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
