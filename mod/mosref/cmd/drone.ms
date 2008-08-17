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

(module "mosref/cmd/drone")
(import "mosref/shell")
(import "mosref/node")
(import "mosref/listener")

(define-cmd "drone"
            "drone <file> <id> <platform>"
            (string-append
              "Creates a new drone executable for the specified platform"
              " and places it at file, then spawns a listener on the"
              " current node.  When the drone connects to the listener, a"
              " the drone will be bound to the specified identifier.")

  (define file (req-path (mosref-shell-console shell)
                         terms " for drone executable"))
  (define id (req-term terms " drone identifier"))
  (define platform (req-term terms " drone platform"))
  (define node (mosref-shell-node shell))
  (define session-private (make-private-key))
  (define session-public (find-public-key session-private))
  (define addr (node-addr node))
  (unless addr
    (send-err " node address unknown, use set addr to assign one"))
  (define portno (node-port node))
  (define sin (node-make-sin node portno))
  (define data (guard (lambda (e)
                        (send-err "Could not compile drone."))
                 (make-drone-exe addr sin portno session-public platform)))
  (guard (lambda (e)
           (send-err "Could not write file " (format (cadr file)) "."))
    (put-node-file @file data))

  (send-line "Drone executable created.")

  (define next (make-drone-node id node sin session-private))
  (set-node-prop! next 'platform platform)
  
  (spawn-drone-listener node next))

(define (spawn-drone-listener node next)
  (define portno (node-port node))

  (define id (node-id next))
  (define sin (drone-node-sin next))
  (define ecdh (drone-node-ecdh next))

  (send-line "Listening for drone on " (format portno) "...")

  (spawn (function (drone-listener)
           (define session #f)
           (define transport #f)

           (define (attempt-affiliation)
             (set! session 
               (guard (lambda (e)
                        (traceback e)
                        (send-line "ERROR: Listener for " id "failed, "
                                   (car (error-info e)) ".")
                        #f)
                 (node-sin-listen node portno sin)))

             (unless session (return))

             (set! transport 
               (guard (lambda (e)
                        ;TODO: Only traceback if error is not
                        ;      an affiliation error.
                        (traceback e)
                        (send-line "ERROR: Affilation of " id 
                                   " failed, " (car (error-info e)) 
                                   ".")
                        #f)
                 (apply console-affiliation ecdh (cdr session)))))

           (until transport (attempt-affiliation))
          
           (define peer (car session))

           (send-line "Drone " id " affiliated from address " 
                      (format-ipv4 peer) ".")

           (set-node-online! next #t)
           (set-node-bridge! next (spawn-endpoint console-endpoint 
                                                  console-broken 
                                                  @transport)))))

(export spawn-drone-listener node next)

(define *node-sin-listen-prog* 
  (inline (export nothing)
          (import "mosref/listener")
          (import "mosref/patch")
          (define bridge *drone-bridge*)
          (define what (wait))
          (define conn (mosref-sin-listen @what))
          (define lane (make-reserved-lane bridge))
          (patch2 conn lane)
          (send (list 'connect 
                      #f ;(peer-addr conn) ;TODO:ADDR
                      (lane-tag lane)))
          (send 'close)))

(define (node-sin-listen (<drone-node> node) portno sin)
  (define conn (spawn-node-program node *node-sin-listen-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (define lanes (make-queue))
  (define bridge (drone-node-bridge node))

  (send (list portno sin) xmit)

  (define event (wait recv))

  (send 'close xmit)

  (when (and (pair? event)
             (eq? (car event) 'connect))
    (define data (cdr event))
    (define addr (car data))
    (define tag (cadr data))
    (define lane (find-reserved-lane bridge tag))
    (when lane 
      (return (list addr (lane-xmit lane) (lane-recv lane)))))

  (error 'mosref "Bogus message while waiting for session lane" event))

(define (node-sin-listen (<console-node> node) portno sin)
  (define portno (node-port node))
  (define conn (mosref-sin-listen portno sin))
  (list #f ;(peer-addr conn) ;TODO:ADDR
    (output conn) (input conn)))

(define *node-make-sin-prog*
  (inline (export nothing)
          (import "mosref/listener")
          (send (make-mosref-sin (wait)))))

(define (node-make-sin (<drone-node> node) portno)
  (define conn (spawn-node-program node *node-make-sin-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))

  (send portno xmit)
  
  (define event (wait recv))
  
  (send 'close xmit)

  (when (string? event)
    (return event))

  (error 'mosref 
         "Bogus message while waiting for service identification number" event))

(define (node-make-sin (<console-node> node) portno)
  (make-mosref-sin portno))

(export node-sin-listen node-make-sin)
