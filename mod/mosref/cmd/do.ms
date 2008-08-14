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

(module "mosref/cmd/do")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "do"
            "do <lisp-expr>"
            (string-append
              "Evaluates the supplied lisp expression on the current node,"
              " and outputs the result.")

  (define expr (apply string-join " " (tc->list terms)))
  (eval-node-expr (mosref-shell-node shell) (string->exprs expr)))

(define *drone-eval-prog*
  (inline (export nothing) ;; All private..
          (import "lib/cons-filter")
          (import "lib/format-filter")
          
          (define okay #t)
          (define result #f)
          
          (define progn (wait))
            
          (define result
            (with-output (output-chain (output) ;TODO: Does not work.
                                       (cons-filter 'out)
                                       (format-filter))
              (guard (function (fwd-traceback err)
                       (define s (make-string))
                       (traceback err s)
                       (set! okay #f)
                       s)
                 (format (progn)))))

          (send (cons (if okay 'succ 'fail) result))
          (send 'close)))
                
(define (eval-node-expr (<console-node> node) expr)
  (guard traceback (send-line ":: " (format (exec expr)))))

(define (eval-node-expr (<drone-node> node) expr)
  (with-node-program node *drone-eval-prog*
    (send (assemble (optimize (compile expr))) xmit)                 
    (define done #f)
    (until done
      (define evt (expect-signal recv))
      (define key (car evt))
      (define val (cdr evt))
      ;(print "GOT: ") (print (format evt)) (print *line-sep*)
      (case key
        ((out) (when (string? val) (send-line val)))
        ((fail) (when (string? val) (send-line val))
                (set! done #t))
        ((succ) (when (string? val) (send-line ":: " val))
                (set! done #t))))
    (send 'close xmit)))

(export eval-node-expr)
