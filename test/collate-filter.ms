; Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
;  
; This library is distributed in the hope that it will be useful, but WITHOUT  
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or  
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License  
; for more details. 
;  
; You should have received a copy of the GNU Lesser General Public License  
; along with this library; if not, write to the Free Software Foundation,  
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  
;  

(import "lib/test")
(import "lib/filter")
(import "lib/collate-filter")

(enable-spot-tests)

(define xmit (make-queue))
(define recv (input-chain xmit (check-collation-filter)))

(send "\0\0\0\5alpha\0\0\0\4beta\0\0\0\7charlie" xmit)

(s: (wait 100 recv))
(r: "alpha")

(s: (wait 100 recv))
(r: "beta")

(s: (wait 100 recv))
(r: "charlie")

(send "\0\0\0\5alpha" xmit)
(send "\0\0" xmit)
(send "\0\4beta\0\0\0\7charlie\0" xmit)

(s: (wait 100 recv))
(r: "alpha")

(s: (wait 100 recv))
(r: "beta")

(s: (wait 100 recv))
(r: "charlie")

(s: (wait 100 recv))
(r: 'timeout)

