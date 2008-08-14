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

(module "lib/buffer-channel")
(import "lib/filter")

(define (buffer-channel channel)
  (buffer-channel/2 channel (make-queue)))

(define (buffer-channel/2 channel debris)
  (define buffer (make-string))

  (define (more)
    (define evt (wait channel))
    ;;; TODO: We need to do something about fail events.
    (if (string? evt)
      (string-append! buffer evt)
      (send evt debris)))

  (function (read-channel-buffer amt)
    ;;; TODO: We need to use timeouts, here.            
    (while (< (string-length buffer) amt)
      (more))
    (string-read! buffer amt)))

(export buffer-channel buffer-channel/2)

