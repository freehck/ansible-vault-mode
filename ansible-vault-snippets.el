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

;; ──────────────────────────────────────────────────────────────
;; Internal variables
;; ──────────────────────────────────────────────────────────────


(defvar ansible-vault--tempdir (expand-file-name "emacs-ansible-vault-mode" temporary-file-directory)
  "Temporary clean directory to run ansible-vault binary in.

We use it because in order to ensure ansible-vault binary won't be able
to find any ansible.cfg file to use.")

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
    ;; eblk
    (eblk-regex . ansible-vault--eblk-regex)
    (eblk-find-all-in-buffer . ansible-vault--eblk-find-all-in-buffer)
    (make-eblk-orig . make-ansible-vault--eblk)
    (make-eblk . ansible-vault--make-eblk)
    (eblk-overlay . ansible-vault--eblk-overlay)
    (eblk-ehdr . ansible-vault--eblk-ehdr)
    (eblk-last-saved-content . ansible-vault--eblk-last-saved-content)
    (eblk-p . ansible-vault--eblk-p)
    (eblk-overlay-content . ansible-vault--eblk-overlay-content)
    (eblk-enc-content . ansible-vault--eblk-enc-content)
    (eblk-decypt . ansible-vault--eblk-decrypt)
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
;; Data Structures
;; ──────────────────────────────────────────────────────────────

;; ehdr: Encryption Header

(defconst ansible-vault--ehdr-regex
  (rx line-start "$ANSIBLE_VAULT;"
      (group-n 1 "1." (any "12")) ";"
      (group-n 2 "AES" (optional "256"))
      (optional ";" (group-n 3 (+ any)))
      line-end)
  "Regex to find and parse Encryption Header.")

(defconst ansible-vault--ehdr-regex-groups
  (a-list :version 1
          :cipher-algorithm 2
          :vault-id 3))

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

;; eblk: Encrypted Blocks

(cl-defstruct ansible-vault--eblk
  "Encrypted Blocks (eblk)."
  overlay ehdr last-saved-content)

(defun ansible-vault--eblk-overlay-content (eblk)
  "Return all text hidden by eblk overlay."
  (ansible-vault--with-local-aliases
    (let ((ov (eblk-overlay eblk)))
      (buffer-substring-no-properties (overlay-start ov) (overlay-end ov)))))

(defun ansible-vault--eblk-enc-content (eblk)
  "Return ansible-vault encrypted text hidden by eblk overlay."
  (ansible-vault--with-local-aliases
    (when-let* ((ovc (eblk-overlay-content eblk))
                (_ (string-match eblk-regex ovc))
                (indent (match-string 1 ovc))
                (ec-orig (match-string 2 ovc))
                (ec (replace-regexp-in-string (rx line-start (literal indent)) "" ec-orig)))
      ec)))

(defface ansible-vault--eblk-content-face
  '((t :background "dark slate grey"))
  "Decrypted and clean."
  :group 'ansible-vault)

(defface ansible-vault--eblk-header-face
  '((t :background "red4"))
  "Decrypted and clean."
  :group 'ansible-vault)

(defun ansible-vault--make-eblk (&rest plist)
  "Constructor eblk."
  (ansible-vault--with-local-aliases
    (cond
     ((and (plist-member plist :start)
           (plist-member plist :end))
      (let ((eblk (make-eblk-orig :overlay (make-overlay (copy-marker (plist-get plist :start))
                                                         (copy-marker (plist-get plist :end))))))
        (overlay-put (eblk-overlay eblk) 'face 'ansible-vault--eblk-content-face)
        (overlay-put (eblk-overlay eblk) 'before-string
             (propertize "ansible-vault encrypted block\n" 'face 'ansible-vault--eblk-header-face))
        (when-let ((enc-content (eblk-enc-content eblk)))
          (setf (eblk-ehdr eblk)
                (make-ehdr :parse-string (first-line enc-content))))
        eblk))
     (t (apply #'make-eblk-orig plist)))))

(defconst ansible-vault--eblk-regex
  (rx
   "!vault" (+ space) "|" (or "\n" "\r\n")
   (group (* space))
   (group (+ nonl) (or "\n" "\r\n")
          (* (seq (backref 1) (+ nonl) (or "\n" "\r\n")))
          (backref 1) (+ nonl)))
  "Return regex to match entire !vault | block with consistent indent.")

(defun ansible-vault--eblk-find-all-in-buffer ()
  "Find all eblk's."
  (ansible-vault--with-local-aliases
    (save-excursion
      (widen)
      (goto-char (point-min))
      (let ((eblks '()))
        (while (re-search-forward eblk-regex nil t)
          (when-let* ((start (match-beginning 0))
                      (end (match-end 0)))
            ;;(push (list start end) eblks) ; for debug purposes
            (push (make-eblk :start start :end end) eblks)))
        (nreverse eblks)))))

(defun ansible-vault--eblk-decrypt (eblk avo)
  "Decrypt eblk."
  (ansible-vault--with-local-aliases
    (let* ((ov (eblk-overlay eblk))
           (ehdr (eblk-ehdr eblk))
           (enc-content (eblk-enc-content eblk))
           (content (av-decrypt avo ehdr enc-content)))
      (progn
        (overlay-put ov 'display content)
        (setf (eblk-last-saved-content eblk) content)
        (overlay-put ov 'face nil)
        (overlay-put ov 'modified nil)))))

  

;; ──────────────────────────────────────────────────────────────
;; Misc
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--get-or-create-error-buffer ()
  "Generate or return `ansible-vault' error report buffer."
  (or (get-buffer "*ansible-vault-error*")
      (let ((buffer (get-buffer-create "*ansible-vault-error*")))
        (with-current-buffer buffer)
          (setq-local buffer-read-only t)
        buffer)))

;; ──────────────────────────────────────────────────────────────
;; Shell
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--gen-shell-command (action avo ehdr)
  (ansible-vault--with-local-aliases
    (let ((command (list ansible-vault-command)))
      (cl-flet ((cpush (elt) (push elt command)))
      (pcase action
        (:decrypt
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
        (:encrypt
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

;; TODO: probably it'll be sane to return some structure indicating status: okay or error
;; it would be useful to indicate errors while decrypting/encrypting eblks
(defun ansible-vault--run (action avo ehdr str)
  ""
  (ansible-vault--with-local-aliases
    (let ((command (gen-shell-command action avo ehdr))
          (cmd-buf-stdout (generate-new-buffer "ansible-vault-cmd-stdout"))
          (cmd-buf-stderr (generate-new-buffer "ansible-vault-cmd-stderr"))
          (env-ansible-vault-password-file (getenv "ANSIBLE_VAULT_PASSWORD_FILE")))
      (unless (f-directory-p ansible-vault--tempdir)
        (make-directory ansible-vault--tempdir))
      (unwind-protect
          (pcase (unwind-protect
                     (progn
                       (when env-ansible-vault-password-file
                         (setenv "ANSIBLE_VAULT_PASSWORD_FILE" nil))
                       (with-temp-buffer
                         (insert str)
                         (let ((inhibit-message t) ; disable output to *Messages* from elisp `message' function
                               (message-log-max nil) ; disable output to *Messages* from c-code
                               (default-directory ansible-vault--tempdir))
                           (shell-command-on-region (point-min) (point-max)
                                                    command
                                                    cmd-buf-stdout nil
                                                    cmd-buf-stderr nil)
                           )))
                   (when env-ansible-vault-password-file
                     (setenv "ANSIBLE_VAULT_PASSWORD_FILE" env-ansible-vault-password-file)))
            (0 (with-current-buffer cmd-buf-stdout
                 (buffer-string)))
            (_ (progn
                 (switch-to-buffer (ansible-vault--get-or-create-error-buffer))
                 (goto-char (point-max))
                 (insert "$ " command "\n")
                 (insert-buffer-substring cmd-buf-stderr)
                 (insert "\n"))))
        (kill-buffer cmd-buf-stdout)
        (kill-buffer cmd-buf-stderr)
        ))))

(defalias 'ansible-vault--decrypt (apply-partially #'ansible-vault--run :decrypt))
(defalias 'ansible-vault--encrypt (apply-partially #'ansible-vault--run :encrypt))





;;;;;;
