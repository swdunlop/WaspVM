; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2012, Chris Double <chris.double@double.co.nz>
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

; Provides the ability to spawn a terminal connected to the returned stream.

(module "lib/terminal")
(import "lib/env")
;(import "lib/foe")

(define *in-screen*  (or (env-is  "TERMINAL" "screen") ;; From the manpage
                         (env-is  "TERM" "screen")))   ;; From the source.. Way to go..

(define has-util
  (if *in-win32*
    (function (has-util/win32 name)
      (member name '("nc")))

    (function (has-util/posix name)
      (locate-cmd name))) )

(define *has-xterm*  (has-util "xterm"))
(define *has-screen* (has-util "screen"))
(define *has-netcat* (has-util "nc"))
(define *has-rlwrap* (has-util "rlwrap"))
(define *has-osascript* (if *in-macosx* (has-util "osascript")))

(define (bg-command cmd)
  (if *in-win32*
    (string-append "cmd /c start " cmd)
    (string-append cmd " &")))

(define (run-terminal title portno)
  (define inner-cmd
    (cond
      ((not *has-netcat*)
       (error 'term "This version of lib/terminal requires netcat"))
      (*has-rlwrap*
        (string-append "rlwrap nc 127.0.0.1 " (format portno)))
      (else
        (string-append "nc 127.0.0.1 " (format portno)))))

  (define cmd (cond
                ((and *in-screen* *has-screen*)
                 (string-append "screen -t '" title "' " inner-cmd))
                ((and *in-x11* *has-xterm*)
                 (bg-command 
                   (string-append "xterm -T '" title "' -e " inner-cmd)))
                (*in-win32*
                 (bg-command 
                   (string-append "cmd /c \"title '" title 
                                  "' && " inner-cmd "\"")))
                (*has-osascript*
                  ;; And you thought win32 was bad..
                  (string-append 
                    "open -a terminal; "
                    "echo 'tell application \"Terminal\"\n"
                               "activate\n"
                               "do script \"" inner-cmd "\"\n"
                          "end tell' | osascript"))
                (else
                  (error 'term "Cannot determine how to get a new window."))))

  (unless (= (run-command cmd) 0)
    (error 'term "Failed attempt to spawn terminal" cmd)))

;;TODO: This should be site configured.
(define *min-accept* 30000)
(define *max-accept* 40000)

(define (spawn-terminal title)

  (define portno #f)
  (define listener #f)

  (until listener
    (set! portno (random-integer *min-accept* *max-accept*))
    (set! listener (guard (lambda (err) #f)
                     (serve-tcp portno))))

  (guard (lambda (err)
           (send 'close listener)
           (re-error err))
    (run-terminal title portno))

  ;;TODO: Timeout.
  (define stream (wait listener))
  (close-service listener)
  stream)

(export spawn-terminal)

