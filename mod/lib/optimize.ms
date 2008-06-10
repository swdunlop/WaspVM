; Copyright (C) 2006, Ephemeral Security, LLC 
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
;  

; Optimization:
; Any LDB LDC LDG followed by NEWF or another load may be culled

(module "lib/optimize")

(define (optimize assembly)
  (define pending (make-tc))
  (define completed (make-tc))
  (define result (make-tc))
  (define instr #f)

  (define (next)
    (if instr
      (tc-prepend! completed instr))
    (set! instr (tc-next! pending))
    instr)

  (define (rewind)
    (tc-prepend! pending instr)
    (set! instr (tc-next! completed)))

  (define (yield instr)
    (tc-append! result instr))

  (define (pass)
    (yield instr))

  (define (more?)
    (not (tc-empty? pending)))
 
  (define (optimize-rag)
    (cond 
      ((not (more?)) (pass))
      ((symbol? (next)) (rewind) (pass))
      ((eq? (car instr) 'retn)
       (yield '(retn))) ; Our optimization for rag;retn is retn. 
      (else (rewind) (pass))))

  (define (optimize-call)
    (cond 
      ((not (more?)) (pass))
      ((symbol? (next)) (rewind) (pass))
      ((eq? (car instr) 'retn)
       (yield '(tail))) ; Our optimization for call;retn is tail.
      (else (rewind) (pass))))

  (define (optimize-dead-branch)
    ;Our optimization for (j[ft] branch) branch is to simulate the test with
    ;a drop.
    (define branch (cadr instr))
    (cond
      ((not (more?)) (pass))
      ((not (symbol? (next))) (rewind) (pass))
      ((not (eq? instr branch)) (rewind) (pass))
      (else
        (yield branch))))

  (define (optimize-one-jump)
    ;Our optimization for (jmp branch) branch is to drop the instruction, but
    ;keep the branch.
    (define branch (cadr instr))
    (cond
      ((not (more?)) (pass))
      ((not (symbol? (next))) (rewind) (pass))
      ((not (eq? instr branch)) (rewind) (pass))
      (else (rewind))))
    
  (tc-splice! pending assembly)

  (while (more?)
         (next)
         (if (symbol? instr) 
           (pass)
           (case (car instr)
             ((jf jt) (optimize-dead-branch))
             ((jmp) (optimize-one-jump))
             ((call) (optimize-call))
             ((rag) (optimize-rag))
             (else (pass)))))

  (tc->list result))

(export optimize)
