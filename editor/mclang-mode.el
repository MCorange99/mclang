;;; mclang-mode.el --- Major Mode for editing mclang source code -*- lexical-binding: t -*-

;; Copyright (C) 2022 MCorange <gvidasjuknevicius2@gmail.com>

;; Author: MCorange <gvidasjuknevicius2@gmail.com>
;; URL: https://github.com/mcorange9/mclang

;; Permission is hereby granted, free of charge, to any person
;; obtaining a copy of this software and associated documentation
;; files (the "Software"), to deal in the Software without
;; restriction, including without limitation the rights to use, copy,
;; modify, merge, publish, distribute, sublicense, and/or sell copies
;; of the Software, and to permit persons to whom the Software is
;; furnished to do so, subject to the following conditions:

;; The above copyright notice and this permission notice shall be
;; included in all copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
;; BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
;; ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;; SOFTWARE.

;;; Commentary:
;;
;; Major Mode for editing MCLang source code. It's Forth but written in Python.

;; TODO: jump to the opposite side of the blocks with C-M-f and C-M-b
;; I think tuareg-mode can do that with similar end-like block, we try
;; to steal their approach
;; TODO: color the names of definitions in const, memory, proc, etc differently

(defconst mclang-mode-syntax-table
  (with-syntax-table (copy-syntax-table)
    ;; C/C++ style comments
	(modify-syntax-entry ?/ ". 124b")
	(modify-syntax-entry ?* ". 23")
	(modify-syntax-entry ?\n "> b")
    ;; Chars are the same as strings
    (modify-syntax-entry ?' "\"")
    (syntax-table))
  "Syntax table for `mclang-mode'.")

(eval-and-compile
  (defconst mclang-keywords
    '("if" "else" "while" "do" "include" "memory" "fn"
      "const" "end" "offset" "reset" "assert" "in" "inline"
      "here" "addr-of" "call-like" "let" "peek")))

(defconst mclang-highlights
  `((,(regexp-opt porth-keywords 'symbols) . font-lock-keyword-face)))

;;;###autoload
(define-derived-mode porth-mode prog-mode "porth"
  "Major Mode for editing MClang source code."
  :syntax-table mclang-mode-syntax-table
  (setq font-lock-defaults '(mclang-highlights))
  (setq-local comment-start "// "))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.mcl\\'" . porth-mode))

(provide 'mclang-mode)

;;; mclang-mode.el ends here
