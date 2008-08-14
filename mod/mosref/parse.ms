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

(module "mosref/parse")
(import "mosref/format")

(define *rx-dns* (make-regex "^[A-Za-z][A-Za-z._-]+"))
(define *rx-addr* (make-regex "^[0-9.]+$"))
(define *rx-cidr* (make-regex "^([0-9.]+)/([0-9]+)"))
(define *rx-addr-range* (make-regex "^([0-9.]+)-([0-9.]+)$"))

(define (cidr-host-mask bits) (- (<< 1 (- 32 bits)) 1))

(define (parse-mask s)
  (define i (string->integer s))
  (when (or (< i 1)
            (> i 32))
    (error 'parse "CIDR IPv4 masks must be in the range [1,32]" s))
  (cidr-host-mask i)) 

(define (cidr-min net mask)
  (& net (! mask)))

(define (cidr-max net mask)
  (| net mask))

(define (parse-host-spec s)
  (map (function (parse-host-range r)
          (define m (match-regex *rx-dns* r))
            (when m (return m))
              
          (define m (match-regex *rx-addr* r))
          (when m (return (resolve-addr m)))
              
          (define m (match-regex *rx-addr-range* r))
          (when m (return (list (resolve-addr (car m))
                                (resolve-addr (cadr m)))))
             
          (define m (match-regex *rx-cidr* r))
          (when m 
            (define h (resolve-addr (car m)))
            (define d (parse-mask (cadr m)))
            (return (list (cidr-min h d)
                          (cidr-max h d))))
         
          (error 'parse 
            "expected a host address, CIDR network or address range." 
            r))

       (string-split* s ",")))

(define (parse-port s)
  (define n (guard (lambda (x) (error 'parse "expected a port" s))
                   (string->integer s)))
  (when (or (< n 0) (> n 65535))
    (error 'parse "expected a port in the range 0 to 65535." n))
  n)

(define *rx-port* (make-regex "^[0-9]+$"))
(define *rx-range* (make-regex "^([0-9]+)-([0-9]+)$"))

(define (parse-port-spec s)
  (map (function (parse-port-range r)
         (define m (match-regex *rx-port* r))              
              
         (when m (return (parse-port m)))

         (define m (match-regex *rx-range* r))

         (when m (return (list (parse-port (car m))
                               (parse-port (cadr m)))))
                            
         (error 'parse "expected either a port, or a port range" r))
       (string-split* s ",")))

(export parse-port-spec parse-host-spec)

(define (opt-term terms)
  (when (tc-empty? terms) (return #f))
  (define str (tc-next! terms)))

(define (opt-integer terms for)
  (when (tc-empty? terms) (return #f))
  (define str (tc-next! terms))
  (guard (lambda (e)
           (send-err "Could not parse " for "."))
         (string->integer str)))

(define (req-term terms . what)
  (when (tc-empty? terms)
    (apply send-err "Expected " what))
  (tc-next! terms))

(define (req-node terms for)
  (define id (req-term terms "node identifier" for "."))
  (define node (find-mosref-node id))
  (unless node
    (send-err "Could not find " (format id) for ".")))

(define (req-path current-node terms for)
  (define path (req-term terms "file path" for "."))
  (unless (string-find path ":")
    (return (list current-node path)))
  (set! path (string-split path ":"))
  (define id (car path))
  (set! path (cadr path))
  (define node (find-mosref-node id))
  (unless node
    (send-err "Could not find node " (format id) for "."))
  (list node path))

(export opt-term req-term req-node req-path opt-integer)

(define (parse-flag val)
  (cond ((member val '("Yes" "yes" "YES" "True" "TRUE" "true"))
         #t)
        ((member val '("No" "no" "NO" "False" "FALSE" "false"))
         #f)
        (else (error 'parse "expected boolean value" (format val)))))

(export parse-flag parse-port)
