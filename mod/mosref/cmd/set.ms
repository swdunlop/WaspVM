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

(module "mosref/cmd/set")

(import "mosref/shell")
(import "mosref/node")
(import "mosref/props")

(define-cmd "set"
            "set [<key>[=<value>] [<command>]]"
            (string-append
              "If no key is supplied, lists properties associated with the"
              " current node.  If a key and value is supplied, assigns the"
              " supplied value to the key, for the current node.  If only"
              " the key is supplied, the value is assumed to be \"true\"."
              "\n\n"
              "If a command is furnished, in addition to a key, it will be"
              "performed after the property has been updated."
              "\n\n"
              "The word 'set' may be omitted, if the key=value form is used.")

  (define node (mosref-shell-node shell))
  (define key-val (opt-term terms))
  (define command (if (and key-val (not (tc-empty? terms))) terms #f))

  (when key-val
    (set! key-val (parse-property key-val)))
  
  (cond (command (set-node-prop! node @key-val)
                 (do-mosref-cmd shell command))
        (key-val (set-node-prop! node @key-val)
                 (send-line "Set."))
        (else    (send-line "Properties: "
                            (apply string-join "\n            " 
                                         (map format-property 
                                              (list-node-props node)))))))

(define (format-property key-val) 
  (define key (car key-val))
  (define val (cdr key-val))
  (string-append (format key) " = " (format-propval key val)))

(define (parse-property key-val)
  (set! key-val (string-split key-val "="))
  (define key (resolve-key (car key-val)))
  (define val (if (null? (cdr key-val))  #t 
                                         (cadr key-val)))
  (set! val (validate-prop key val))
  (list key val))

(export format-property parse-property)
