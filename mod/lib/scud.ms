(module "lib/scud")
(import "lib/env")
(import "lib/record")

"This module provides a quick, simple abstraction of common VT100 commands"
"used foring rich console user interfaces.  We do not use curses,"
"because it will just get in our way."

"NOTE: Print is used, instead of send, because on Windows, many of these"
"commands must be done synchronously."

;;;TODO: POSIX: Store foreground and background in module namespace.
;;;TODO: POSIX: For special 'clear background, just reset and reuse fg.
;;;TODO: Find way for POSIX to get screen dimensions.

(define dict make-dict)

;;;IRGB
;;;8421
(define *conio-fg-colors* (dict (cons 'black          0)
                                (cons 'red            4)
                                (cons 'green          2)
                                (cons 'brown          6)
                                (cons 'blue           1)
                                (cons 'magenta        5) 
                                (cons 'cyan           3)
                                (cons 'grey           7)
                                (cons 'dark-red       4)
                                (cons 'dark-green     2)
                                (cons 'dark-brown     6)
                                (cons 'dark-blue      1)
                                (cons 'dark-magenta   5)
                                (cons 'dark-cyan      3)
                                (cons 'dark-grey      7)
                                (cons 'bright-red     12)
                                (cons 'bright-green   10)
                                (cons 'bright-brown   14)
                                (cons 'bright-blue    9)
                                (cons 'bright-magenta 13)
                                (cons 'bright-cyan    11)
                                (cons 'bright-grey    15)
                                (cons 'white          15)))

(define *conio-bg-colors* (dict (cons 'black          0)
                                (cons 'red            64)
                                (cons 'green          32)
                                (cons 'brown          96)
                                (cons 'blue           16)
                                (cons 'magenta        80) 
                                (cons 'cyan           48)
                                (cons 'grey           112)))

(define *vt100-bg-colors* (dict (cons 'black          "40")
                                (cons 'red            "41")
                                (cons 'green          "42")
                                (cons 'brown          "43")
                                (cons 'blue           "44")
                                (cons 'magenta        "45")
                                (cons 'cyan           "46")
                                (cons 'gray           "47")))

(define *vt100-fg-colors* (dict (cons 'black          "30")
                                (cons 'red            "31")
                                (cons 'green          "32")
                                (cons 'brown          "33")
                                (cons 'blue           "34")
                                (cons 'magenta        "35")
                                (cons 'cyan           "36")
                                (cons 'grey           "37")
                                (cons 'dark-red       "2;31")
                                (cons 'dark-green     "2;32")
                                (cons 'dark-brown     "2;33")
                                (cons 'dark-blue      "2;34")
                                (cons 'dark-magenta   "2;35")
                                (cons 'dark-cyan      "2;36")
                                (cons 'dark-grey      "2;37")
                                (cons 'bright-red     "1;31")
                                (cons 'bright-green   "1;32")
                                (cons 'bright-brown   "1;33")
                                (cons 'bright-blue    "1;34")
                                (cons 'bright-magenta "1;35")
                                (cons 'bright-cyan    "1;36")
                                (cons 'bright-grey    "1;37")
                                (cons 'white          "1;37")))

;TODO: Determine how to poll for updates, write a function for it,
;      export that function and cause send-vt100 and scud-print to call it.

(define (lookup table color)
  (cond ((symbol? color)
         (set! color (dict-ref table color))
         (scud-assert "Color name not valid." color)
         color)

        ((integer? color) (number->string color))

        (else (error 'scud "Color must be an integer or a symbol."))))

(define (vt100-bg color) (lookup *vt100-bg-colors* color))
(define (vt100-fg color) (lookup *vt100-fg-colors* color))
(define (conio-bg color) (lookup *conio-bg-colors* color))
(define (conio-fg color) (lookup *conio-fg-colors* color))

(define (vt100-cmd key . fields)
  (print (if (null? fields)
          (string-append 27 key)
          (string-append 27 "[" (string-join ";" @fields) key))
       ))
  
(define (scud-assert msg okay)
  "If the supplied value, okay, is non-false, an error is raised with the"
  "supplied text."

  (unless okay (error 'scud msg)))

(osdef (scud-cls)
  "Clears the entire and sets cursor to 0, 0."
  (*in-winnt* (conio-cls) (conio-goto 1 1))
  (else (vt100-cmd "J" "2") (vt100-cmd "f" "0;0")))

(osdef (scud-clear)
  "Clears from the current column on the current row to the end of the row."
  (*in-winnt* (conio-clear))
  (else (vt100-cmd "[K")))

(osdef (scud-goto row col)
  "Positions the cursor at row, col."

  (*in-winnt* (conio-goto row col))
  (else (vt100-cmd "f" (format row) (format col))))

(define (scud-print . data)
  "Prints the specified data at the current position."
  (print (string-append @data)))

(osdef (set-scud-bg color)
  "Sets the background of the to the specified color, found in"
  "*vt100-bg-colors*."
    
  (*in-winnt* (conio-set-attr #f (conio-bg color)))
  (else (vt100-cmd "m" (vt100-bg color))))

(osdef (set-scud-fg color)
  "Sets the foreground of the to the specified color found in"
  "*vt100-fg-colors*."

  (*in-winnt* (conio-set-attr (conio-fg color) #f))
  (else (vt100-cmd "m" (vt100-fg color))))

(osdef (set-scud-colors bg fg)
  "Sets the foreground of the to the specified color found in"
  "*vt100-fg-colors*; also resets any other attributes."

  (*in-winnt* (conio-set-attr (conio-fg fg) (conio-bg bg)))
  (else (vt100-cmd "m" "0" (vt100-bg bg) (vt100-fg fg))))

(export scud-goto scud-clear scud-cls scud-print set-scud-fg set-scud-bg 
        set-scud-colors)


