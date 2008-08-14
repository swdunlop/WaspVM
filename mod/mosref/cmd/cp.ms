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

(module "mosref/cmd/cp")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "cp" 
            "cp <src-file> <dst-file>" 
            (string-append
              "Copies source file to the destination file.  Either the source"
              " or the destination file path may be on a drone or console; to"
              " specify a path on a node other than the console, preface"
              " the path with the node name, and a colon.")

  (define console (mosref-shell-console shell))
  (define node (mosref-shell-node shell))
  (define src (req-path console terms " for source file"))
  (define dst (req-path console terms " for destination file"))

  (send-line "Copy from " (format-path src) " to " (format-path dst))
                       
  (define data (guard (lambda (e) 
                        (send-err "Could not access file " 
                                  (format (cadr src)) "."))
                      (get-node-file @src)))
                       
  (guard (lambda (e) 
           (traceback e)
           (send-err
             "Could not alter file "
             (format (cadr dst)) "."))
         (put-node-file @dst data)))

(define *drone-get-file-prog*
  (inline (let ((path (wait))
                (data #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
                   (set! data (read-data-file path))
                   (until (empty-string? data)
                          (send (string-read! data 16384)))
                   (send 'done)))
          (send 'close)))

(define (get-node-file (<console-node> node) path)
  (read-data-file path))

(define (get-node-file (<drone-node> node) path)
  (with-node-program node *drone-get-file-prog*
     (send path xmit)
     (define data (make-string))
     (forever ;TODO: Bad, we can't use forever/return in w-n-p
       (define evt (expect-data recv))
       (cond
         ((eq? evt 'done) (return data))
         ((string? evt) (string-append! data evt))
         (else (error 'expect "expected string or done" evt))))))

(define *drone-put-file-prog*
  (inline (let ((path (wait))
                (data (make-string))
                (done #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
              (until done
                (define evt (wait))
                (cond ((eq? evt 'done) (set! done #t))
                      ((string? evt) (string-append! data evt))
                      (else (error 'fail "expected string or done" evt))))
              (write-data-file path data))
              (send '(succ)))
          (send 'close)))

(define (put-node-file (<console-node> node) path data)
  (write-data-file path data))

(define (put-node-file (<drone-node> node) path data)
  (with-node-program node *drone-put-file-prog*
    (send path xmit)
    (until (empty-string? data)
      (send (string-read! data 16384) xmit))
    (send 'done xmit)
    (expect-succ recv)))

(export get-node-file put-node-file)
