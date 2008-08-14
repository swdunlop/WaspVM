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

(module "lib/catch")

; Given a list of cases -- each in the form of ((key ...) stmt ...), and 
; a block to evaluate, constructs a guard block that will catch errors,
; and pass them to the specified clause if encountered, as "err".

; If an else case is omitted, errors that do not match any of the clauses
; will be re-error'd.

(define-macro (catch-case cases . body)
  (unless (assq 'else cases)
    (set! cases (append cases '((else (re-error err))))))

  `(guard (lambda (err)
             (case (error-key err)
               ,@cases))
     ,@body))

(define-macro (catch-cond conds . body)
  (unless (assq 'else conds)
    (set! conds (append conds '((else (re-error err))))))

  `(guard (lambda (err)
             (cond ,@conds))
     ,@body))

(export catch-case catch-cond)

