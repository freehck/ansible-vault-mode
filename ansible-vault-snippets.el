;;; ansible-vault.el --- Minor mode for editing files encrypted by ansible-vault -*- lexical-binding: t; -*-

;; Copyright (C) 2016-2025 Zachary Elliott
;; Copyright (C) 2025-20.. Dmitrii Kashin
;;
;; Authors: Zachary Elliott <contact@zell.io>, Dmitrii Kashin <freehck@yandex.ru>
;; Maintainer: Dmitrii Kashin <freehck@yandex.ru>
;; URL: http://github.com/freehck/ansible-vault-mode
;; Created: 2016-09-25
;; Version: 1.0.0
;; Keywords: ansible, ansible-vault, tools
;; Package-Requires: ((emacs "27.1") (auto-minor-mode "20180527.1") (a "1.0")

;; This file is not part of GNU Emacs.

;;; Commentary:

;; A mode to work with files encrypted by ansible-vault like if they're ordinary ones.
;;
;; Decryption and encryption processes are automatic.  You can just open encrypted files and they
;; will be decrypted by fly.  When you make changes, just save a file as usual with C-x C-s, and it
;; will be re-encrypted back.
;;
;; Parameters for ansible-vault are taken from an ansbile.cfg file.  The ansible.cfg file path is
;; determined either by ANSIBLE_CONFIG unix env variable, or by an upward search from current file
;; path.
;;
;; Feel safe to change major modes after the mode enabled: it will persist, and won't forget to
;; re-encrypt file before save.
;;
;; For now the mode works only with fully encrypted files, and does not support in-line
;; ansible-vault snippets.

;;; License:

;; This program is free software; you can redistribute it and/or modify it under the terms of the
;; GNU General Public License version 3 as published by the Free Software Foundation.

;; This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
;; even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License along with GNU Emacs; see the
;; file COPYING.  If not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
;; Floor, Boston, MA 02110-1301, USA.

;;; Code:

;; ──────────────────────────────────────────────────────────────
;; Dependencies
;; ──────────────────────────────────────────────────────────────

(require 'cl-lib) ;; for normal folding functions
(require 'pcase) ;; for pattern-matching functions
(require 'subr-x)
(require 'map)
(require 'a) ;; for alist functions
(require 'auto-minor-mode) ;; to enable the mode automatically when open encrypted file
(require 'transient) ;; for interactive menu

;; ──────────────────────────────────────────────────────────────
;; Constants
;; ──────────────────────────────────────────────────────────────

(defconst ansible-vault-version "0.7.0"
  "`ansible-vault' version.")

;; ──────────────────────────────────────────────────────────────
;; Customizable variables
;; ──────────────────────────────────────────────────────────────

(defgroup ansible-vault nil
  "`ansible-vault' application group."
  :group 'applications
  :link '(url-link :tag "Website for ansible-vault-mode"
                   "https://github.com/freehck/ansible-vault-mode")
  :prefix "ansible-vault-")

(defcustom ansible-vault-command "ansible-vault"
  "`ansible-vault' shell command."
  :type 'string
  :group 'ansible-vault)

(defcustom ansible-vault-password-file nil
  "File containing `ansible-vault' password.

This file is used for encryption and decryption of ansible vault
files.  If it is set to nil `ansible-vault-mode' will prompt
you for a password."
  :type 'string
  :group 'ansible-vault)

(defcustom ansible-vault-vault-id-alist '()
  "Associative list of strings containing (vault-id . password-file) pairs.

This list allows for managing `ansible-vault' password files via
the 1.2 vault-id syntax."
  :type '(alist :key-type string :value-type string)
  :group 'ansible-vault)

(defcustom ansible-vault-minor-mode-prefix "C-c a"
  "Chord prefix for ansible-vault minor mode."
  :type 'string
  :group 'ansible-vault)

(defcustom ansible-vault-auto-decrypt t
  "Automatically decrypt when the mode is enabled on an encrypted buffer."
  :type 'boolean
  :group 'ansible-vault)

(defcustom ansible-vault-auto-determine-major-mode-by-decrypted-content t
  "Try to determine an appropriate major mode after decrypting a buffer.

Affects only the first mode initialization"
  :type 'boolean
  :group 'ansible-vault)

(defcustom ansible-vault-mode-enable-by-magic t
  "If set to t, add the the mode to auto-minor-mode-magic-alist.

Works only when set before `ansible-vault' is loaded.
If it's already loaded, use `ansible-vault-mode-enable-by-magic'
function instead."
  :type 'boolean
  :group 'ansible-vault)

(defcustom ansible-vault-mode-eblk-header-text "AV Enc"
  "Text of an ansible-vault in-line encrypted block overlay header."
  :type 'string
  :group 'ansible-vault)

;; ──────────────────────────────────────────────────────────────
;; Internal variables
;; ──────────────────────────────────────────────────────────────

(defvar ansible-vault--tempdir (expand-file-name "emacs-ansible-vault-mode" temporary-file-directory)
  "Temporary clean directory to run ansible-vault binary in.

We use it because in order to ensure ansible-vault binary won't be able
to find any ansible.cfg file to use.")

;; ──────────────────────────────────────────────────────────────
;; Local variables
;; ──────────────────────────────────────────────────────────────

(defvar ansible-vault--state '()
  "Permanent local variable to keep the `ansible-vault-mode' state.

Its value is OBJ where (`ansible-vault--state-p' OBJ) evaluates to t.")
(make-variable-buffer-local 'ansible-vault--state)
(put 'ansible-vault--state 'permanent-local t)

;; ──────────────────────────────────────────────────────────────
;; Faces
;; ──────────────────────────────────────────────────────────────

(defface ansible-vault--eblk-content-face
  '((t :background "dark slate grey"))
  "In-line encrypted block overlay content face."
  :group 'ansible-vault)

(defface ansible-vault--eblk-header-face
  '((t :background "red4"))
  "In-line encrypted block overlay header face."
  :group 'ansible-vault)

(defface ansible-vault--buffer-header-face
  '((t :background "red4"))
  "Buffer overlay header face."
  :group 'ansible-vault)

;; ──────────────────────────────────────────────────────────────
;; Misc Useful Functions
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--first-line (str)
  "Return the first line of multiline string STR (without a newline)."
  (if (string-match "\n" str)
      (substring str 0 (match-beginning 0))
    str))

;; ──────────────────────────────────────────────────────────────
;; Local Namespacing Hack
;; ──────────────────────────────────────────────────────────────

;; plus maybe eval-when-compile

(defconst ansible-vault--local-aliases
  '(;; misc
    (first-line . ansible-vault--first-line)
    (with-temp-env . ansible-vault--with-temp-env)
    ;; shell
    (gen-shell-command . ansible-vault--gen-shell-command)
    (av-run . ansible-vault--run)
    (av-decrypt . ansible-vault--decrypt)
    (av-encrypt . ansible-vault--encrypt)
    ;; ehdr
    (make-ehdr-orig . make-ansible-vault--ehdr)
    (make-ehdr . ansible-vault--make-ehdr)
    (ehdr-cipher-algorithm . ansible-vault--ehdr-cipher-algorithm)
    (ehdr-vault-type . ansible-vault--ehdr-vault-type)
    (ehdr-vault-id . ansible-vault--ehdr-vault-id)
    (ehdr-p . ansible-vault--ehdr-p)
    (ehdr-regex . ansible-vault--ehdr-regex)
    (ehdr-regex-groups . ansible-vault--ehdr-regex-groups)
    (ehdr-parse . ansible-vault--ehdr-parse)
    ;; vault-id-alist
    (make-vault-id-alist . ansible-vault--make-vault-id-alist)
    ;; avo
    (make-avo-orig . make-ansible-vault--avo)
    (make-avo . ansible-vault--make-avo)
    (avo-ansible-cfg-path . ansible-vault--avo-ansible-cfg-path)
    (avo-password-file . ansible-vault--avo-password-file)
    (avo-vault-id-alist . ansible-vault--avo-vault-id-alist)
    (avo-default-enc-vault-id . ansible-vault--avo-default-enc-vault-id)
    (avo-default-vault-id . ansible-vault--avo-default-vault-id)
    (avo-p . ansible-vault--avo-p)
    (avo-locate-ansible-cfg . ansible-vault--avo-locate-ansible-cfg)
    ;; buffer
    (buffer-encrypted-p . ansible-vault--buffer-encrypted-p)
    (buffer-decrypt . ansible-vault--buffer-decrypt)
    (whole-buffer-string . ansible-vault--whole-buffer-string)
    ;; state
    (make-state-orig . make-ansible-vault--state)
    (make-state . ansible-vault--make-state)
    (state-avo . ansible-vault--state-avo)
    (state-overlays . ansible-vault--state-overlays)
    (state-buffer-overlay . ansible-vault--state-buffer-overlay)
    (state-p . ansible-vault--state-p)
;;    ;; eblk
;;    (eblk-regex . ansible-vault--eblk-regex)
;;    (eblk-find-all-in-buffer . ansible-vault--eblk-find-all-in-buffer)
;;    (make-eblk-orig . make-ansible-vault--eblk)
;;    (make-eblk . ansible-vault--make-eblk)
;;    (eblk-overlay . ansible-vault--eblk-overlay)
;;    (eblk-ehdr . ansible-vault--eblk-ehdr)
;;    (eblk-last-saved-content . ansible-vault--eblk-last-saved-content)
;;    (eblk-p . ansible-vault--eblk-p)
;;    (eblk-overlay-content . ansible-vault--eblk-overlay-content)
;;    (eblk-enc-content . ansible-vault--eblk-enc-content)
;;    (eblk-decypt . ansible-vault--eblk-decrypt)
    ;; shell
    (gen-shell-command . ansible-vault--gen-shell-command)
    (av-decrypt . ansible-vault--decrypt)
    (av-encrypt . ansible-vault--encrypt)
    )
  "Just a shortcuts for all the functions in `ansible-vault'.")

(defun ansible-vault--expand-local-aliases (form)
  "Recusively substitute aliases from `ansible-vault--local-aliases' in FORM."
  (cond
   ((and (symbolp form)
         (assoc form ansible-vault--local-aliases))
    `,(cdr (assoc form ansible-vault--local-aliases)))
   ((and (consp form)
         (symbolp (car form))
         (assoc (car form) ansible-vault--local-aliases))
    `(,(cdr (assoc (car form) ansible-vault--local-aliases))
      ,@(mapcar #'ansible-vault--expand-local-aliases (cdr form))))
   ((and (consp form)
         (eq (car form) 'function)
         (consp (cdr form))
         (symbolp (cadr form))
         (assoc (cadr form) ansible-vault--local-aliases))
    `(function ,(cdr (assoc (cadr form) ansible-vault--local-aliases))))
   ((consp form)
    (cons (ansible-vault--expand-local-aliases (car form))
          (if (listp (cdr form))
              (mapcar #'ansible-vault--expand-local-aliases (cdr form))
            (ansible-vault--expand-local-aliases (cdr form)))))
   (t form)))

(defmacro ansible-vault--with-local-aliases (&rest body)
  (declare (indent 0))
  `(progn
     ,@(mapcar #'ansible-vault--expand-local-aliases body)))

;; ──────────────────────────────────────────────────────────────
;; Shell (how to run ansible-vault command)
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--gen-shell-command (action avo ehdr)
  "Generates ansible-vault command to run.

ACTION is either 'encrypt or 'decrypt.
AVO is an `ansible-vault--avo' structure (ansible-vault options).
EHDR is and `ansible-vault--ehdr' structure (ansible-vault encryption header).

Return string you can pass to `shell-command-on-region'."
  (ansible-vault--with-local-aliases
    (let ((command (list ansible-vault-command)))
      (cl-flet ((cpush (elt) (push elt command)))
      (pcase action
        ('decrypt
         (cpush "decrypt")
         (cpush "--output=-")
         (pcase (ehdr-vault-type ehdr)
           ('password-file (pcase (avo-password-file avo)
                             (`nil (error "Unknown vault-password-file"))
                             (val  (cpush "--vault-password-file")
                                   (cpush val))))
           ('vault-id      (pcase (avo-vault-id-alist avo)
                             (`nil (error "Unknown vault-identity-list"))
                             (vidl (cl-loop for (id . file) in vidl
                                            do (progn (cpush "--vault-id")
                                                      (cpush (concat id "@" file)))))))
           (ver            (error (format "Unknown ansible-vault crypto-header version: %s" ver)))))
        ('encrypt
         (cpush "encrypt")
         (cpush "--output=-")
         (pcase (ehdr-vault-type ehdr)
           ('password-file (pcase (avo-password-file avo)
                             (`nil (error "Unknown vault-password-file"))
                             (val  (cpush "--vault-password-file")
                                   (cpush val))))
           ('vault-id      (let ((enc-id (or (ehdr-vault-id ehdr)
                                             (avo-default-enc-vault-id avo))))
                             (unless enc-id
                               (error "Undefined vault-encrypt-identity"))
                             (cpush "--encrypt-vault-id")
                             (cpush enc-id)
                             (pcase (avo-vault-id-alist avo)
                               (`nil (error "Unknown vault-identity-list"))
                               (vidl (cl-loop for (id . file) in vidl
                                              when (equal id enc-id)
                                              do (progn (cpush "--vault-id")
                                                        (cpush (concat id "@" file))))))))
           (ver (error (format "Unknown ansible-vault crypto-header version: %s" ver)))))
        (_ (error (format "Unknown action: %s" action))))
      (mapconcat #'identity (reverse command) " ")))))

(defmacro ansible-vault--with-temp-env (bindings &rest body)
  "Execute BODY with temporarily modified environment variables.

BINDINGS is a list of:
  (VAR . VAL)  -> set VAR to VAL (VAL = nil -> remove)
  VAR          -> remove VAR (equivalent to (VAR . nil))

All changes are automatically restored on exit."
  (declare (indent 1) (debug (sexp &rest form)))
  (let ((saved-sym (gensym "--env-saved--"))
        (bindings (cl-loop for item in bindings
                           for var = (if (consp item) (car item) item)
                           for val = (if (consp item) (cdr item) nil)
                           collect (list 'cons var val))))
    `(let ((,saved-sym (cl-loop for (var . new-val) in (list ,@bindings)
                                collect (cons var (getenv var)))))
       (unwind-protect
           (progn
             (cl-loop for (var . new-val) in (list ,@bindings)
                      do (setenv var new-val))
             ,@body)
         (cl-loop for (var . old-val) in ,saved-sym
                  do (setenv var old-val))))))

(defun ansible-vault--run (action avo ehdr str)
  "Run ansible-vault command (defined by `ansible-vault-command').

ACTION is either 'encrypt or 'decrypt.
AVO is an `ansible-vault--avo' structure (ansible-vault options).
EHDR is and `ansible-vault--ehdr' structure (ansible-vault encryption header).

STR can be a string to perform action on.
STR cab be a cons: `(ok . STR)
STR can be a cons: `(error . _)

Returns `(ok . result-string) or `(error . error-string)."
  (setq str (pcase str
              (`(ok . ,str) str)
              (`(error . ,str) error)
              (str str)))
  (ansible-vault--with-local-aliases
    (unless (f-directory-p ansible-vault--tempdir)
      (make-directory ansible-vault--tempdir))
    (let ((command (gen-shell-command action avo ehdr))
          (cmd-buf-stdout (generate-new-buffer "ansible-vault-cmd-stdout"))
          (cmd-buf-stderr (generate-new-buffer "ansible-vault-cmd-stderr")))
      (unwind-protect
          (pcase
              (with-temp-buffer
                (insert str)
                (let ((inhibit-message t) ; disable output to *Messages* from elisp `message' function
                      (message-log-max nil) ; disable output to *Messages* from c-code
                      (default-directory ansible-vault--tempdir))
                  (ansible-vault--with-temp-env ("DEFAULT_VAULT_PASSWORD_FILE"    "ANSIBLE_VAULT_PASSWORD_FILE"
                                                 "DEFAULT_VAULT_IDENTITY_LIST"    "ANSIBLE_VAULT_IDENTITY_LIST"
                                                 "DEFAULT_VAULT_IDENTITY"         "ANSIBLE_VAULT_IDENTITY"
                                                 "DEFAULT_VAULT_ENCRYPT_IDENTITY" "ANSIBLE_VAULT_ENCRYPT_IDENTITY"
                                                 "DEFAULT_VAULT_ID_MATCH"         "ANSIBLE_VAULT_ID_MATCH")
                    (shell-command-on-region (point-min) (point-max)
                                             command
                                             cmd-buf-stdout nil
                                             cmd-buf-stderr nil))
                  ))
            (0 (with-current-buffer cmd-buf-stdout `(ok . ,(buffer-string))))
            (_ (with-current-buffer cmd-buf-stderr `(error . ,(buffer-string)))))
        (kill-buffer cmd-buf-stdout)
        (kill-buffer cmd-buf-stderr)
        ))))

(defalias 'ansible-vault--decrypt (apply-partially #'ansible-vault--run 'decrypt)
  "(ansible-vault--decrypt EVO EHDR STR)
Alias to (ansible-vault--run 'decrypt AVO EHDR STR).")

(defalias 'ansible-vault--encrypt (apply-partially #'ansible-vault--run 'encrypt)
  "(ansible-vault--encrypt EVO EHDR STR)
Alias to (ansible-vault--run 'encrypt AVO EHDR STR).")

;; ──────────────────────────────────────────────────────────────
;; Data Structures
;; ──────────────────────────────────────────────────────────────

;; ehdr: Encryption Header

(defconst ansible-vault--ehdr-regex
  (rx line-start
      (group-n 1 (* space))
        "$ANSIBLE_VAULT;"
      (group-n 2 "1." (any "12")) ";"
      (group-n 3 "AES" (optional "256"))
      (optional ";" (group-n 4 (+ (not space)))))
  "Regex to find and parse Encryption Header.")

(defconst ansible-vault--ehdr-regex-groups
  (a-list :indent 1
          :version 2
          :cipher-algorithm 3
          :vault-id 4))

(cl-defstruct ansible-vault--ehdr
  "Encryption Header (ehdr)."
  cipher-algorithm vault-type vault-id)

(defun ansible-vault--make-ehdr (&rest plist)
  "Constructor ehdr."
  (ansible-vault--with-local-aliases
    (cond
     ;; by keys with defaults
     ((or (plist-member plist :cipher-algorithm)
          (plist-member plist :vault-type)
          (plist-member plist :vault-id))
      (make-ehdr-orig :cipher-algorithm (or (plist-get plist :cipher-algorithm) "AES256")
                      :vault-type (plist-get plist :vault-type)
                      :vault-id (plist-get plist :vault-id)))
     ;; by parsing header
     ((plist-member plist :parse-string)
      (let ((str (plist-get plist :parse-string)))
        (unless (string-match ehdr-regex str)
          (error "Not an Encryption Header for ansible-vault: %s" str))
        (make-ehdr :cipher-algorithm (match-string (a-get ehdr-regex-groups :cipher-algorithm) str)
                   :vault-type (pcase (match-string (a-get ehdr-regex-groups :version) str)
                                 ("1.1" 'password-file)
                                 ("1.2" 'vault-id)
                                 (_ nil))
                   :vault-id (match-string (a-get ehdr-regex-groups :vault-id) str))))
     ;; by avo
     ;; by state
     ;; default constructor fallback
     (t (apply #'make-ehdr-orig plist)))))



;; vault-id-alist

(defun ansible-vault--make-vault-id-alist (&rest plist)
  (ansible-vault--with-local-aliases
    (cond
     ;; by parsing string
     ((plist-member plist :parse-string)
      (let ((str (plist-get plist :parse-string))
            (dir (plist-get plist :basedir)))
        (cl-loop for id-file-str in (split-string str ", ")
                 for (id file) = (split-string id-file-str "@")
                 when (and id file
                           (not (equal file "prompt")))
                 for file = (if (and (f-relative file) dir)
                                (expand-file-name file dir)
                              file)
                 collect (cons id file))))
     ;; by ready-to-use alist
     ((plist-member plist :alist)
      (plist-get plist :alist))
     ;; default w/o arguments is a fallback to alist
     (t (make-vault-id-alist :alist plist)))))



;; avo: Ansible-Vault Options

(cl-defstruct ansible-vault--avo
  "Ansible-vault options (avo)."
  ansible-cfg-path password-file vault-id-alist default-enc-vault-id default-vault-id)

(defun ansible-vault--make-avo (&rest plist)
  "Constructor avo."
  (ansible-vault--with-local-aliases
    (cond
     ;; by keys with defaults omited (default constructor fallback is okay)
     ;; by ansible.cfg file
     ((plist-member plist :ansible-cfg-path)
      (pcase (plist-get plist :ansible-cfg-path)
        ((and ansible-cfg-path
              (guard (stringp ansible-cfg-path))
              (guard (file-readable-p ansible-cfg-path)))
         (let ((ansible-cfg-content (with-temp-buffer (insert-file-contents ansible-cfg-path) (buffer-string))))
           (cl-flet ((parse-key (key)
                       (let ((rx (rx line-start (literal key) (zero-or-more blank) "=" (zero-or-more blank)
                                     (group-n 1 (minimal-match (one-or-more not-newline)))
                                     (zero-or-more blank) (zero-or-more ";" (zero-or-more not-newline)) line-end)))
                         (when (string-match rx ansible-cfg-content)
                           (match-string 1 ansible-cfg-content)))))
             (make-avo-orig :ansible-cfg-path ansible-cfg-path
                            :default-enc-vault-id (parse-key "vault_encrypt_identity")
                            :default-vault-id (parse-key "vault_identity")
                            :password-file (expand-file-name (parse-key "vault_password_file")
                                                             (f-dirname ansible-cfg-path))
                            :vault-id-alist (make-vault-id-alist :parse-string (parse-key "vault_identity_list")
                                                                 :basedir (f-dirname ansible-cfg-path))))))
        (`nil (make-avo))))
     ;; by current buffer
     ((plist-member plist :by-current-buffer)
      (make-avo :ansible-cfg-path (avo-locate-ansible-cfg)))
     ;; default fallback
     (t (apply #'make-avo-orig plist)))))
                                                         
(defun ansible-vault--avo-locate-ansible-cfg ()
  (cl-flet ((check-file (file) (and file (file-readable-p file) t))
            (upward-search (from-path file) (expand-file-name file (locate-dominating-file from-path file))))
    (let* ((possible-sources (list (getenv "ANSIBLE_CONFIG")
                                   (upward-search buffer-file-name "ansible.cfg")
                                   "~/.ansible.cfg"
                                   "/etc/ansible/ansible.cfg"))
           (valid-sources (cl-remove-if-not #'check-file possible-sources)))
      (unless valid-sources (error "No ansible.cfg found"))
      (cl-first valid-sources))))


;; BUFFER

(defun ansible-vault--buffer-encrypted-p (&optional buffer)
  "Return t if first line of buffer BUFFER matches `ansible-vault--ehdr-regex'.
BUFFER can be a buffer or buffer name.  If nil or omitted, use current buffer."
  (ansible-vault--with-local-aliases
    (save-excursion
      (goto-char (point-min))
      (let ((buffer-first-line (string-trim-right (or (thing-at-point 'line t) ""))))
        (and (string-match ehdr-regex buffer-first-line t))))))

(defun ansible-vault--buffer-decrypt (&optional avo ehdr)
  "Decrypt current buffer."
  (ansible-vault--with-local-aliases
    (pcase (list (or avo (state-avo av-state))
                 (or ehdr (overlay-get (state-buffer-overlay av-state) 'ehdr)))
      ((and `(,avo ,ehdr)
            (guard (avo-p avo))
            (guard (ehdr-p ehdr)))
       (let ((enc-content (whole-buffer-string)))
         (erase-buffer)
         (prog1 (pcase (av-decrypt avo ehdr enc-content)
                  (`(ok . ,str)     (insert str)
                                    `(ok . ,enc-content))
                  (`(error . ,err)  (insert err)
                                    `(error . err)))
           (set-buffer-modified-p nil))))
      (_ `(error . "ansible-vault buffer-decrypt: bogus AVO or EHDR.")))))

(defun ansible-vault--whole-buffer-string ()
  "Return whole buffer as string.
Like `buffer-string' but ignores narrowing."
  (save-restriction
    (widen)
    (buffer-string)))

;; OVERLAY

;; any overlay must contain enc-content, ehdr

;; ansible-vault--overlay-refresh-header ;; -> to refresh header
;; ansible-vault--overlay--init

;;(defun ansible-vault--overlay-refresh-buffer-header ()
  




;; STATE

;;(pcase (cons 'ok2 "xxx")
;;  (`(ok1 . ,_) "yay")
;;  (`(ok2 . ,x) x)
;;  (x x))

(cl-defstruct ansible-vault--state
  "Ansible-vault-mode internal state structure."
  avo
  overlays
  buffer-overlay)

(defun ansible-vault--make-state (&rest plist)
  (ansible-vault--with-local-aliases
    (cond
     ((plist-member plist :by-current-buffer)
      ;; create state
      (let ((state (make-state-orig)))
        (prog1 state
          ;; set avo in any case
          (setf (state-avo state)
                (make-avo :by-current-buffer))
          ;; if buffer's encrypted, first decrypt it, then make overlay
          ;; save enc-content and ehdr in overlay properties
          (pcase (buffer-encrypted-p)
            (`t (let ((enc-content (whole-buffer-string))
                      (ehdr (make-ehdr :parse-string (first-line enc-content)))
                      (decryption-result (buffer-decrypt (state-avo state) ehdr))
                      (ov (make-overlay (copy-marker (point-min))
                                        (copy-marker (point-max)))))
                  (setf (state-buffer-overlay state) ov)
                  (overlay-put ov 'enc-content enc-content)
                  (overlay-put ov 'ehdr ehdr)
                  (pcase 
                    (`(ok . ,_)
                     ;; TODO: find and set inline overlays
                     nil
                     )
                    (`(error . ,err)
                     ;; in case of decryption error, make buffer overlay readonly
                     (overlay-put ov 'invisible t)
                     (overlay-put ov 'display (whole-buffer-string))
                     ))))
            (`nil
             ;; if buffer's unencrypted, just make an overlay
             (let ((ov (make-overlay (copy-marker (point-min))
                                     (copy-marker (point-max)))))
               (setf (state-buffer-overlay state) ov))
             ;; TODO: find and set inline overlays
             ))))))))
               
                
                     

                    
                    
              
                        
        
        
      













;;(cl-defstruct ansible-vault--bufstate
;;  "Ansible-vault buffer state."
;;  encrypted
;;  enc-content
;;  ehdr
;;  overlay)
;;
;;(defun ansible-vault--make-bufstate (&rest plist)
;;  (ansible-vault--with-local-aliases
;;    (cond
;;     ((and (plist-member plist :encrypted)
;;           (plist-get plist :encrypted))
;;      (let ((buffer-string (buffer-string)))
;;        (make-bufstate-orig :encrypted t
;;                            :enc-content buffer-string
;;                            :ehdr (make-ehdr :parse-string
;;                                             (first-line buffer-string)))))
;;     ((plist-member plist :by-current-buffer)
;;      (make-bufstate :encrypted (and (string-match ehdr-regex (first-line (buffer-string))) t)))
;;     (t (apply #'make-bufstate-orig plist)))))
;;
;;
;;(defun ansible-vault--make-state (&rest plsit)
;;  (ansible-vault--with-local-aliases
;;    (cond
;;
;;  
;;
;;
;;;;;; NB: the concept of encrypted blocks as a top-level objects fails
;;;;;; decided to switch to create overlays, and set encrypted blocks as their properties
;;;; eblk: Encrypted Blocks
;;
;;
;;
;;(defconst ansible-vault--eblk-regex
;;  (rx
;;   "!vault" (+ space) "|" (group-n 1 "\n")
;;   (group-n 2 (* space))
;;   (group-n 3
;;     "$ANSIBLE_VAULT;1." (any "12") ";" "AES" (optional "256") (optional ";" (+ (not space))) "\n"
;;     (* (seq (backref 1) (+ nonl) "\n"))
;;     (backref 1) (+ nonl)))
;;  "Return regex to match entire ansible-vault in-line encrypted block with indent.")
;;
;;(defconst ansible-vault--eblk-regex-groups
;;  (a-list :indent 2 :content 3))
;;
;;(cl-defstruct ansible-vault--eblk
;;  "Encrypted Blocks (eblk)."
;;  overlay
;;  ehdr
;;  last-saved-encrypted-content
;;  is-modified
;;  is-miltiline)
;;
;;(defun ansible-vault--make-eblk (&rest plist)
;;  "Constructor eblk."
;;  (ansible-vault--with-local-aliases
;;    (cond
;;     ((and (plist-member plist :start)
;;           (plist-member plist :end))
;;      (let ((eblk (make-eblk-orig :overlay (make-overlay (copy-marker (plist-get plist :start))
;;                                                         (copy-marker (plist-get plist :end))))))
;;        (overlay-put (eblk-overlay eblk) 'face 'ansible-vault--eblk-content-face)
;;        eblk))
;;     (t (apply #'make-eblk-orig plist)))))
;;
;;(defun ansible-vault--eblk-refresh-overlay-header (eblk)
;;  "Generate and set a header to an ansible-vault encrypted block EBLK."
;;  (ansible-vault--with-local-aliases
;;    (let* ((terminator (if eblk-is-multiline "\n" ": "))
;;           (before-string
;;            (pcase (eblk-ehdr eblk)
;;              (`nil (concat ansible-vault-mode-eblk-header-text terminator))
;;              (ehdr (let ((type (symbol-name (ehdr-vault-type ehdr)))
;;                          (vid (ehdr-vault-id ehdr)))
;;                      (setq before-string
;;                            (concat ansible-vault-mode-eblk-header-text
;;                                    " (" type (if vid (concat ", " vid) "") ")" terminator))))))
;;           (before-string-with-props
;;            (propertize before-string 'face 'ansible-vault--eblk-header-face)))
;;      (overlay-put (eblk-overlay eblk)
;;                   'before-string before-string-with-props))))
;;
;;(defun ansible-vault--eblk-get-overlay-content (eblk)
;;  "Return all text hidden by eblk overlay."
;;  (ansible-vault--with-local-aliases
;;    (let ((ov (eblk-overlay eblk)))
;;      (buffer-substring-no-properties (overlay-start ov) (overlay-end ov)))))
;;
;;
;;
;;
;;
;;;; (when-let ((enc-content (eblk-enc-content eblk)))
;;;;   (setf (eblk-ehdr eblk)
;;;;         (make-ehdr :parse-string (first-line enc-content))))
;;;; (eblk-refresh-overlay-header eblk)
;;
;;
;;
;;
;;
;;
;;
;;
;;
;;
;;
;;(defun ansible-vault--eblk-enc-content (eblk)
;;  "Return ansible-vault encrypted text hidden by eblk overlay."
;;  (ansible-vault--with-local-aliases
;;    (when-let* ((ovc (eblk-overlay-content eblk))
;;                (_ (string-match eblk-regex ovc))
;;                (indent (match-string 1 ovc))
;;                (ec-orig (match-string 2 ovc))
;;                (ec (replace-regexp-in-string (rx line-start (literal indent)) "" ec-orig)))
;;      ec)))
;;
;;
;;
;;(defun ansible-vault--eblk-find-all-in-buffer ()
;;  "Find all eblk's."
;;  (ansible-vault--with-local-aliases
;;    (save-excursion
;;      (widen)
;;      (goto-char (point-min))
;;      (let ((eblks '()))
;;        (while (re-search-forward eblk-regex nil t)
;;          (when-let* ((start (match-beginning 0))
;;                      (end (match-end 0)))
;;            ;;(push (list start end) eblks) ; for debug purposes
;;            (push (make-eblk :start start :end end) eblks)))
;;        (nreverse eblks)))))
;;
;;(defun ansible-vault--eblk-decrypt (eblk avo)
;;  "Decrypt eblk."
;;  (ansible-vault--with-local-aliases
;;    (let* ((ov (eblk-overlay eblk))
;;           (ehdr (eblk-ehdr eblk))
;;           (enc-content (eblk-enc-content eblk))
;;           (content (av-decrypt avo ehdr enc-content)))
;;      (progn
;;        (overlay-put ov 'display content)
;;        (setf (eblk-last-saved-content eblk) content)
;;        (overlay-put ov 'face nil)
;;        (overlay-put ov 'modified nil)))))
;;
;;




;;;;;;
