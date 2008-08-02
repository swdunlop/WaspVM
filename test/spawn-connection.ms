; Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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

(import "lib/test")
(import "lib/spawn-connection")
(enable-spot-tests)

(s: (spawn-connection (function (add-1) (forever (send (+ 1 (wait)))))))
(t: (send 1 _)
    (= (wait _) 2))
(t: (send 22 _)
    (= (wait _) 23))
(t: (send 333 _)
    (= (wait _) 334))
(t: (eq? (wait 5 _) 'timeout))

