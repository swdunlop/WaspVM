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

(module "lib/http-file-server")
(import "lib/http-server")

(define *http-file-servers* (make-dict))

(define (find-or-use-server server)
  (if (queue? server)
    server
    (or (dict-ref *http-file-servers* server)
        (spawn-http-file-server server))))

(define (offer-http-file server path type data)
  (set! server (find-or-use-server server))
  (unless (string-begins-with? path "/")
    (set! path (string-append "/" path )))
  (send (list 'offer path 
              (list (string-append "Content-type: " type)) 
              data)
        server)
  server)

(define (withdraw-http-file server path)
  (set! server (find-or-use-server server))
  (unless (string-begins-with? path "/")
    (set! path (string-append "/" path )))
  (send (list 'withdraw path) server)
  server)

(define (spawn-http-file-server portno)
  (define cmds (make-queue))
  (define files (make-dict))

  (define (do-offer path headers data)
    (dict-set! files path (list headers data)))
  
  (define (do-withdraw path)
    (dict-remove! files path))

  (spawn (lambda ()
           (forever
             (define evt (wait cmds))
             (cond ((eq? (car evt) 'offer) (apply do-offer (cdr evt)))
                   ((eq? (car evt) 'withdraw) (apply do-withdraw (cdr evt)))))))

  (spawn-http-server portno
    (lambda (req)
      (define path (url-path (http-request-url req)))
      (print "GET: ")
      (print (format path))
      (print "\n")
      (define file (dict-ref files path))
      (print "File is: ")
      (print (format file))
      (print "\n")
      (if file
        (apply write-http-response req 200 "OK" file)
        (write-http-response req 404 
                             (string-append "File Not Found: " path) 
                             '("Content-type: text/plain" ) 
                             "File not found.\r\nDo not take internally."))))

  (dict-set! *http-file-servers* portno cmds)
  cmds)

(export offer-http-file withdraw-http-file spawn-http-file-server)
