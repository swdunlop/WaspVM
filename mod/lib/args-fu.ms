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

(module "lib/args-fu")

; This provides functionality required to handle Common Lisp-style keyword functions.

; Given a list of keys, and a list of terms in "fu" syntax, scans the terms list and 
; returns an association list.
;
; >> (key-fu '(id: ports: alt:) '(id: http ports: 1 2 3))
; :: ((id: http) (ports: 1 2 3) (alt:))

(define (assq-set! k v a)
  (define l (assq k a))
  (set-cdr! (last-pair l) (list v)))

(define (key-fu keys terms)
  (define args (map list keys))
  (define key #f)
  (for-each (function (key-fu/term term)
               (cond ((memq term keys) (set! key term))
                     (key (assq-set! key term args))
                     (else (error 'fu "expected args to start with a key"
                                  term keys))))
               terms)
  args)

; Returns a list of items after count, and destructively partitions the list before that
; count. Count must be >= 1.
; 
; (define head args)
; (set! args (head-fu head 3))

(define (head-fu count terms)
  (define p (list-refp terms (- count 1)))
  (define after (cdr p))
  (set-cdr! p '())
  after)

; Returns a list of the last count items and destructively partitions.
;
; (define tail (tail-fu count 3))

(define (tail-fu count terms)
  (define p (list-refp terms (- (length terms) count 1)))
  (define after (cdr p))
  (set-cdr! p '())
  after)

; Constructs an expression that will yield each of the arguments specified.
; head-1 head-2 key-a key-b key-c tail-1 tail-2 tail-3
;
; The resulting expression must be eval'd.

(define (args-fu head keys tail terms)
  (define head-terms '())
  (when head 
    (set! head-terms terms)
    (set! terms (head-fu head terms)))

  (define tail-terms (if tail
                       (tail-fu tail terms)
                       '()))

  (define key-terms (if keys
                      (map (lambda (term)
                             (set! term (cdr term))
                             (if (null? term)
                               (cons 'quote term)
                               (cons 'list term)))
                           (key-fu keys terms))))
  (append head-terms key-terms tail-terms))

;; Useful for macros, this result does not need to be eval'd, but does not
;; evaluate any of its terms.
(define (parse-fu head keys tail terms)
  (define head-terms '())
  (when head 
    (set! head-terms terms)
    (set! terms (head-fu head terms)))

  (define tail-terms (if tail
                       (tail-fu tail terms)
                       '()))

  (define key-terms (if keys 
                      (map cdr (key-fu keys terms))
                      '()))

  (append head-terms key-terms tail-terms))

(export args-fu head-fu tail-fu key-fu parse-fu)
