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

(module "mosref/node")

(import "lib/object")
(import "lib/bridge")
(import "lib/filter")
(import "lib/package-filter")
(import "lib/with-io")
(import "lib/args-fu")

(import "mosref/format")

(define *nodes-by-id* (make-dict))
(define *drones-by-bridge* (make-dict))

(define-class node <object>
              (make-node-record id props)
              node?
              (id node-id)
              (props node-props))

(define-class console-node <node>
              (make-console-node-record id props)
              console-node?
              (id node-id)
              (props node-props))

(define-class drone-node <node>
              (make-drone-node-record id props link sin ecdh bridge)
              drone-node?
              (id node-id)
              (sin drone-node-sin)
              (ecdh drone-node-ecdh)
              (link drone-node-link)
              (bridge drone-node-bridge set-drone-node-bridge!)
              (props node-props))

(define (list-mosref-nodes)
  (dict-values *nodes-by-id*))

(define (find-mosref-node id)
  (dict-ref *nodes-by-id* id))

(define (make-console-node addr portno)
  (define node (make-console-node-record "console" (make-dict)))
  (set-node-platform! node *platform*)
  (when addr (set-node-address! node addr))
  (when portno (set-node-port! node portno))
  (set-node-online! node #t)
  (dict-set! *nodes-by-id* "console" node)
  node) 

(define (make-drone-node id link sin ecdh)
  (define node (make-drone-node-record id (make-dict) link sin ecdh #f))
  (dict-set! *nodes-by-id* id node)
  node)

(define (set-node-bridge! node bridge)
  (define old-bridge (drone-node-bridge node))
  (dict-remove! *drones-by-bridge* old-bridge)
  (dict-set! *drones-by-bridge* bridge node)
  (set-drone-node-bridge! node bridge))

(export drone-node-link set-node-bridge! drone-node-sin drone-node-ecdh)

(define (spawn-node-program (<console-node> node) program)
  (define xmit (make-queue))
  (define recv (make-queue))
  (with-input xmit (with-output recv (spawn program)))
  (list xmit recv))

(define (spawn-node-program (<drone-node> node) program)
  (unless (node-online node)
    (error 'off (string-append "Drone " (node-id node) " is offline."))) 
  (define lane (make-lane (drone-node-bridge node)))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

(export list-mosref-nodes find-mosref-node
        spawn-node-program make-drone-node make-console-node node-id 
        drone-node-bridge <node> <drone-node> <console-node> 
        node? drone-node? console-node?)

(define (expect-data recv)
  ;TODO: timeout
  (define evt (wait recv))
  (when (eq? evt 'close)
    (error 'expect "channel closed while expecting data"))
  (guard (lambda (e)
           (apply error 'expect (error-info e)))
    evt))

(define (expect-signal recv)
  (define evt (expect-data recv))
  (unless (pair? evt)
    (error 'expect "got invalid data while expecting signal" evt))
  evt)

(define (expect-succ recv)
  (define evt (expect-signal recv))
  (when (eq? (car evt) 'fail)
    (error 'expect (string-append "expected success, got " (cadr evt))))
  (unless (eq? (car evt) 'succ)
    (error 'expect (string-append "expected success, got " (format evt))))
  (if (null? (cdr evt))
    #t 
    (cadr evt)))
    
(define-macro (with-node-program node program . stmts)
  `(begin
     (define conn (spawn-node-program ,node ,program))
     (define xmit (car conn))
     (define recv (cadr conn))
     (define result (guard (lambda (e)
                             (send 'close xmit)
                            (re-error e))
                      ,@stmts))
    (send 'close xmit)
    result))

(define-macro (inline . body)
  (assemble (optimize (compile body))))

(export inline with-node-program expect-data expect-signal expect-succ)

(define (find-node-prop node key) (dict-ref (node-props node) key))
(define (list-node-props node) (dict->list (node-props node)))
(define (set-node-prop! node key val) (dict-set! (node-props node) key val))
(define (clear-node-prop! node key) (dict-remove! (node-props node) key))
(define (has-node-prop? node key) (dict-set? (node-props node) key))

(export find-node-prop list-node-props set-node-prop! clear-node-prop!
        has-node-prop?)

(define *formatters-by-key* (make-dict))
(define *validators-by-key* (make-dict))
(define *prop-docs-by-term* (make-dict))
(define *prop-keys-by-alt* (make-dict))

(define (register-prop key alts help valid fmt)
  (dict-set! *validators-by-key* key (or valid 
                                         (function (generic-validator x) x)))
  (dict-set! *formatters-by-key* key (or fmt format))
  (when help 
    (dict-set! *prop-docs-by-term* (symbol->string key) help))
  (for-each (lambda (alt)
              (dict-set! *prop-keys-by-alt* (symbol->string alt) key))
            (cons key alts)))

(define-macro (define-prop . meta)
  (define (parse-mosref-prop key help valid format)
    (define alts '())
    (when (list? key)
      (set! alts (cdr key))
      (set! key (car key)))

    `(register-prop ',key 
                    ',alts
                    ,(if (null? help) 
                       #f
                       (apply string-append help))
                    ,(if (null? valid)
                       #f
                       `(function (,(make-symbol 'is-valid- key '?) value)
                           ,@valid))
                    ,(if (null? format)
                       #f
                       `(function (,(make-symbol 'format- key '- 'val) value)
                          ,@format))))

  (apply parse-mosref-prop (parse-fu 1 '(doc: valid: format:) 0 meta)))

(define (resolve-key alt)
  (define key (dict-ref *prop-keys-by-alt* alt))
  (unless key
    (error 'parse "unrecognized property. " alt))
  key)

(define (validate-prop key src)
  (define validator (dict-ref *validators-by-key* key))
  (unless validator
    (error 'parse "unrecognized property." (format key)))
  (validator src))

(define (format-propval key src)
  (define formatter (dict-ref *formatters-by-key* key))
  (unless formatter
    (error 'parse "unrecognized property." (format key)))
  (formatter src))

(export define-prop register-prop validate-prop format-propval resolve-key)

(define (find-drone-by-bridge bridge)
  (dict-ref *drones-by-bridge* bridge))

(export find-drone-by-bridge)

