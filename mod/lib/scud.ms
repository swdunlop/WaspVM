(module "lib/scud")
(import "lib/env")
(import "lib/record")

"This module provides a quick, simple abstraction of common VT100 commands"
"used foring rich console user interfaces.  We do not use curses,"
"because it will just get in our way."

"NOTE: Print is used, instead of send, because on Windows, many of these"
"commands must be done synchronously."
;;;TODO: Move colors to global variables.
;;;TODO: Add set-color primitive.
;;;TODO: POSIX: Store foreground and background in module namespace.
;;;TODO: POSIX: For special 'clear background, just reset and reuse fg.
;;;TODO: Find way for POSIX to get screen dimensions.

(define dict make-dict)

;;;IRGB
;;;8421
(define *colors* (dict))
(define (bind-color code . symbols)
  (for-each (lambda (symbol) (dict-set! *colors* symbol code )) symbols))

(bind-color 0 'black)
(bind-color 1 'red 'dark-red)
(bind-color 2 'green 'dark-green)
(bind-color 3 'brown 'yellow 'dark-yellow)
(bind-color 4 'blue 'dark-blue)
(bind-color 5 'magenta 'dark-magenta)
(bind-color 6 'cyan 'dark-cyan)
(bind-color 7 'light-grey)
(bind-color 8 'grey 'dark-grey)
(bind-color 9 'bright-red 'light-red)
(bind-color 10 'light-green 'bright-green)
(bind-color 11 'light-yellow 'bright-yellow)
(bind-color 12 'light-blue 'bright-blue)
(bind-color 13 'light-magenta 'bright-magenta)
(bind-color 14 'light-cyan 'bright-cyan)
(bind-color 15 'white 'light-white 'bright-white)

(define (color-ref symbol)
  (when (integer? c) (return c))
  (define c (dict-ref *colors* symbol))
  (when c (return c))
  (error 'color "Color not recognized" symbol))

(define-macro (to-color var) `(set! ,var (color-ref ,var)))

;TODO: Determine how to poll for updates, write a function for it,
;      export that function and cause send-vt100 and scud-print to call it.

(define *last-fg* 7)

(define (vt100-cmd key . fields)
  (print (if (null? fields)
          (string-append 27 key)
          (string-append 27 "[" (string-join ";" @fields) key))))
  
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

(define (set-scud-bg color)
  "Sets the background of the to the specified color, found in *colors*."
    
  (when (eq? color 'clear)
    (reset-console-colors)
    (set-console-colors *last-fg* #f)
    (return))

  (to-color color)
  (set-console-colors #f color))

(define (set-scud-fg color)
  "Sets the foreground of the to the specified color found in *colors*."

  (to-color color)
  (when color (set! *last-fg* color))
  (set-console-colors color #f))

(define (set-scud-colors bg fg)
  "Sets the foreground of the to the specified color found in"
  "*vt100-fg-colors*; also resets any other attributes."
    
  (when (eq? bg 'clear)
    (reset-console-colors)
    (set-scud-fg fg)
    (return))

  (to-color bg) 
  (to-color fg) 
  (when fg (set! *last-fg* fg))
  (set-console-colors fg bg))

(osdef (scud-size)
  (*in-winnt* (conio-size))
  (else (tty-size (output))))

(export scud-goto scud-clear scud-cls scud-print set-scud-fg set-scud-bg 
        set-scud-colors scud-size)


