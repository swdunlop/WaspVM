; Copyright (C) 2006, Ephemeral Security, LLC
; With modifications Copyright (C) 2007, Scott W. Dunlop <swdunlop@gmail.com>

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
 
(module "lib/iterate")

; Generators, in Wasp Lisp are functions that, when called, return a
; function that will yield a value each time they are called, or raise an
; error, done, to indicate that they can go no further.

; Iterators are Generators that iterate over a data structure, yielding each
; member in turn.

(define (repeat value)
  "Generates the supplied value ad nauseam."

  (function (infinite-repeat-iterator)
    (return value)))

(define (repeat (#t value) count)
  "Generates the supplied value a fixed number of times."

  (function (finite-repeat-iterator)
    (when (<= count 0)
      (error 'done "out of repetitions"))
    (set! count (- count 1))
    (return value)))

(define (list-iter list)
  "Generates a list iterator."
  
  (function (next-list-iter)
    (unless (pair? list)
      (error 'done "no more items in the list"))
    (define item (car list))
    (set! list (cdr list))
    item))

(define (input-iter input)
  "Generates an input iterator."
  (define done #f)

  (function (input-iterator)
    (when done (error 'done "input is done"))
    (define item (wait input))
    (when (eq? item 'done)
      (set! done #t)
      (error 'done "input is done"))
    item))

(define (vector-iter vector)
  (define ln (vector-length vector))
  (define ix 0)

  (function (vector-iterator)
    (when (>= ix ln)
      (error 'done "no more items in the vector"))

    (define item (vector-ref vector ix))
    (set! ix (+ ix 1))
    item))

(define (iter value)
  "Generates a list, vector, set or dictionary iterator."

  (cond
    ((function? value) value)
    ((list? value)     (list-iter value))
    ((input? value)    (input-iter value))
    ((vector? value)   (vector-iter value))
    ((dict? value)     (list-iter (dict->list value)))
    ((set? value)     (list-iter (set->list value)))
    (else (error 'seq "no standard sequence iterator"
                      value))))

(define (iter* list)
  "Generates a list of iterators, one per value in the supplied list."

  (define tc (make-tc))
  (while (pair? list)
    (tc-add! tc (iter (car list)))
    (set! list (cdr list)))
  (tc->list tc))

(define (next generators)
  "Yields a list of items from the list of generators."

  (define tc (make-tc))
  (while (pair? generators)
    (tc-add! tc ((car generators)))
    (set! generators (cdr generators)))
  (tc->list tc))

(define-macro (with-iter . body)
  `(begin
     (define args (iter* (cons arg0 argN)))

     (guard (function (catch-done err)
              (if (eq? (error-key err) 'done)
                result
                (re-error err)))
       (forever 
         ,@body))))

(define-macro (with-iter-tc . body)
  `(begin
     (define args (iter* (cons arg0 argN)))

     (guard (function (catch-done err)
              (if (eq? (error-key err) 'done)
                (tc->list result)
                (re-error err)))
       (forever 
         ,@body))))

(define (for-each fn arg0 . argN)
  (define result #f)
  (with-iter 
    (set! result (apply fn (next args)))))

(define (imap fn arg0 . argN)
  (define args (iter* (cons arg0 argN)))
  (function (map-iter)
    (apply fn (next args))))

(define (map fn arg0 . argN)
  (iter->list (apply imap fn arg0 argN)))

(define (fold-left fn result arg0 . argN)
  (with-iter
    (set! result (apply fn result (next args)))))

(define (fold-right fn result arg0 . argN)
  (with-iter
    (set! result (fn (scatter (next args)) result))))

(define fold fold-right)

(define (index fn arg0 . argN)
  (define result #f)
  (define ix 0)
  (with-iter
    (when (apply fn (next args))
      (return ix))
    (set! ix (+ ix 1))))

(define (list-index fn lst)
  (define ix (index fn lst))
  ix)

(define (all fn arg0 . argN)
  (define result #t)
  (with-iter
    (unless (apply fn (next args)) (return #f))))

(define (any fn arg0 . argN)
  (define result #f)
  (with-iter
    (set! result (apply fn (next args)))
    (when result (return result))))

(define (find fn seq)
  (set! seq (iter seq))
  (guard (function (catch-done err)
           (when (eq? (error-key err) 'done)
             (return #f)))
    (forever
      (define item (seq))
      (when (fn item)
        (return item)))))

(define (filter fn seq)
  (iter->list (ifilter fn seq)))

(define (ifilter fn seq)
  (define it (iter seq))
  (function (filter-iterator)
    (forever
      (define item (it))
      (when (fn item)
        (return item)))))

(export iter list-iter input-iter repeat 
        for-each map imap
        fold-right fold-left fold 
        list-index 
        all any
        find
        filter ifilter)

; Iterates over the values yielded by each supplied iterator, in turn.
(define (join-iters iter0 . iterN)
  (define (next)
    (guard (lambda (err)
             (unless (and (eq? (error-key err) 'done)
                          (pair? iterN))
              (re-error err))
             (set! iter0 (car iterN))
             (set! iterN (cdr iterN))
             (return (next)))
      (iter0))))

; Returns all integer in the range [min, max)

(define (integer-range min max)
  (define t #f)

  (function (next-integer)
    (unless (< min max)
      (error 'done "out of integers"))
    (set! t min)
    (set! min (+ min 1))
    t))

(define (iter->list iter)
  (define tc (make-tc))
    (guard (lambda (err)
             (unless (eq? (error-key err) 'done)
              (re-error err))
             (return (tc->list tc)))
    (forever
      (tc-add! tc (iter)))))

(export integer-range join-iters iter->list)
