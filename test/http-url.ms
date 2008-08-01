; Copyright (C) 2006, Ephemeral Security, LLC 
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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
(import "lib/http-url")

(enable-spot-tests)

(s: (string->url "http://un:pw@server:99/check?x=1#frag"))
(t: (equal? (url-scheme _) "http"))
(t: (equal? (url-auth _) "un:pw@server:99"))
(t: (equal? (http-url-host _) "server"))
(t: (equal? (http-url-portno _) 99))

(t: (equal? (url-path _) "/check"))
(t: (equal? (url-query _) "x=1"))
(t: (equal? (url-frag _) "frag"))
(t: (equal? (http-url-arg _ "x") "1"))

(t: (http-url? _) #t)
(t: (url? _) #t)
(t: (equal? (percent-decode (url->string _)) "http://un:pw@server:99/check?x=1#frag"))

