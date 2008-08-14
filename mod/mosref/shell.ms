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

(module "mosref/shell")

(import "lib/catch")

(import "mosref/console")
(import "mosref/node")
(import "mosref/parse")
(import "mosref/format")

(define *cmd-term* (make-regex "[^ \r\n\t]+"))
(define *display-count* 0)
(define *displays* (set))

(define (add-shell-display! out)
  (set! *display-count* (+ *display-count* 1))
  (set-add! *displays* out))

(define (remove-shell-display! out)
  (set! *display-count* (- *display-count* 1))
  (set-remove! *displays* out)
  (when (<= *display-count* 0)
    (exit 0)))

(define (alert . rest)
  (define msg (string-append "ALERT: " @rest *line-sep*))

  (for-each (lambda (display) (guard (lambda x x)
                                (send msg display)))
            (set->list *displays*)))

(define-record-type mosref-shell
                    (make-mosref-shell node console running)
                    mosref-shell?
                    (node mosref-shell-node set-mosref-shell-node!)
                    (console mosref-shell-console set-mosref-shell-console!)
                    (running mosref-shell-running set-mosref-shell-running!))

(export <mosref-shell> mosref-shell?
        mosref-shell-node set-mosref-shell-node!
        mosref-shell-console set-mosref-shell-console!
        mosref-shell-running set-mosref-shell-running!)

(define-record-type mosref-cmd
                    (make-mosref-cmd verb usage info impl)
                    mosref-cmd?
                    (verb mosref-cmd-verb)
                    (usage mosref-cmd-usage)
                    (info mosref-cmd-info)
                    (impl mosref-cmd-impl))

(export <mosref-cmd> mosref-cmd?
        mosref-cmd-verb mosref-cmd-usage mosref-cmd-info mosref-cmd-impl)

(define *cmds-by-verb* (dict))

(define (mosref-cmds) (dict-values *cmds-by-verb*))

(define (bind-mosref-cmd verb usage info impl)
  (dict-set! *cmds-by-verb* verb (make-mosref-cmd verb usage info impl)))

(define (find-mosref-cmd verb)
  (dict-ref *cmds-by-verb* verb))

(define-macro (define-cmd verb usage info . body)
  `(bind-mosref-cmd ,verb ,usage ,info 
                    (function (,(make-symbol 'cmd- verb) shell terms)
                                          ,@body)))

(export define-cmd bind-mosref-cmd mosref-cmds find-mosref-cmd)

(define (do-mosref-cmd shell terms)
  (when (string? terms)
    (return (do-mosref-cmd shell 
                           (apply make-tc (or (match-regex* *cmd-term* terms)
                                              '())))))
  (when (tc-empty? terms) (return))

  (define verb (tc-next! terms))

  (when (string-find verb "=")
    (tc-prepend! terms verb)
    (set! verb "set"))

  (define data (dict-ref *cmds-by-verb* verb))
  (unless data
    (send-err "I do not understand " (format verb) "."))
    
  ((mosref-cmd-impl data) shell terms))

; Assumes that each input is precisely one line.
(define (run-mosref-shell console node)
  (add-shell-display! (output))
  (guard (lambda (err)
           (traceback err)
           (remove-shell-display! (output)))
    (define shell (make-mosref-shell node console #t))

    (define (send-prompt)
      (send (string-append (node-id (mosref-shell-node shell)) "> ")))

    (send-prompt)

    (while (mosref-shell-running shell)
      (define cmd (wait))
      (when (eq? cmd 'close) (return))
      (when (string? cmd)
        (catch-case (((syn))
                     ((off) (send-line "OFFLINE: " (car (error-info err))))
                     ((parse) (define info (error-info err))
                              (send-line "PARSE: For " (format (cadr info)) 
                                      ", " (car info))))
          (do-mosref-cmd shell cmd))
        (when (mosref-shell-running shell) 
          (send-prompt))))
  
    (send 'close))
  (remove-shell-display! (output)))

(export run-mosref-shell do-mosref-cmd alert)

