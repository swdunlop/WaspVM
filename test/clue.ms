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

(import "lib/test")
(import "lib/clue")

(enable-spot-tests)

(define db (new-clue-db))

(s: (find-clue db))
(r: '())

(s: (find-clue db customer))
(r: '())

(s: (drop-clue '()))
(r: '())

(s: (clue-db->list db))
(r: '())

(s: (list->clue-db '()))

(define record 
  (put-clue db customer (first-name "John") (last-name "Doe")))

(s: (get-clue record customer))
(r: #t)

(s: (get-clue record first-name))
(r: "John")

(s: (get-clue record last-name))
(r: "Doe")

(s: (get-clue record missing))
(r: #f)

(s: (get-clue record customer last-name first-name missing))
(r: (list #t "Doe" "John" #f))

(s: (get-clue (list record record record)
              customer last-name first-name missing))
(r: (list (list #t "Doe" "John" #f)
          (list #t "Doe" "John" #f)
          (list #t "Doe" "John" #f)))

(put-clue db customer (first-name "Jane") (last-name "Doe"))

(s: (find-clue db (first-name "John")))
(r: (list record))

(s: (find-clue db (last-name "Doe")))
(t: (= (length _) 2))

(drop-clue record)

(s: (find-clue db (first-name "John")))
(r: '())

(s: (find-clue db (last-name "Doe")))
(t: (= (length _) 1))

(drop-clue (find-clue db customer))

(s: (find-clue db))
(t: (= (length _) 0))
