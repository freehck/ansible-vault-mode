;;; ansible-vault.el --- Minor mode for editing files encrypted by ansible-vault -*- lexical-binding: t; -*-

;; Copyright (C) 2016-2025 Zachary Elliott
;; Copyright (C) 2025-20.. Dmitrii Kashin
;;
;; Authors: Zachary Elliott <contact@zell.io>, Dmitrii Kashin <freehck@yandex.ru>
;; Maintainer: Dmitrii Kashin <freehck@yandex.ru>
;; URL: http://github.com/freehck/ansible-vault-mode
;; Created: 2016-09-25
;; Version: 0.7.0
;; Keywords: ansible, ansible-vault, tools
;; Package-Requires: ((emacs "26.1") (auto-minor-mode "20180527.1") (a "1.0")

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

;;(defvar ansible-vault--vault-header-regex
(defvar ansible-vault--header-options-regex
  (rx line-start "$ANSIBLE_VAULT;"
      (group-n 1 "1." (any "12")) ";"
      (group-n 2 "AES" (optional "256"))
      (optional ";" (group-n 3 (+ any)))
      line-end)
  "Regex for `ansible-vault' header for identifying of encrypted buffers.")

;;(defvar ansible-vault--vault-header-regex-groups-alist
(defvar ansible-vault--header-options-regex-groups-alist
  (a-list :version 1
          :cipher-algorithm 2
          :vault-id 3))

;; ──────────────────────────────────────────────────────────────
;; Local variables
;; ──────────────────────────────────────────────────────────────

;; internal state a-list

(defvar ansible-vault--state '())
(make-variable-buffer-local 'ansible-vault--state)
(put 'ansible-vault--state 'permanent-local t)

(defun ansible-vault--get-state (&rest keys)
  (a-get-in ansible-vault--state keys))

(defun ansible-vault--set-state (&rest keys-and-newval)
  (let ((keys (butlast keys-and-newval))
        (newval (car (reverse keys-and-newval))))
    (setq-local ansible-vault--state
                (a-assoc-in ansible-vault--state keys newval))))

;; ──────────────────────────────────────────────────────────────
;; Data Structures
;; ──────────────────────────────────────────────────────────────

;; header-options is an a-list structure with parameters from the first line of ansible-vault's encrypted message

(defconst ansible-vault--header-options-keys
  '(:version :cipher-algorithm :vault-id)
  "Keys available in header-options a-list structure.")

(defun ansible-vault--header-options-p (obj)
  "Checks if OBJ is a valid header-options (a-list)."
  (and (a-associative-p obj)
       (a-get obj :version)
       (a-get obj :cipher-algorithm)
       (pcase (a-get obj :version)
         ("1.1" t)
         ("1.2" (a-get obj :vault-id))
         (_     nil))
       t))

(defun ansible-vault--header-options--parse (header)
  (unless (string-match ansible-vault--header-options-regex header)
    (error (format "Not an ansible-vault header: %s" header)))
  (cl-reduce
   (pcase-lambda (acc `(,key . ,n))
     (pcase (match-string n header)
       ((and val (guard val))  (a-assoc-in acc (list key) val))
       (_                      acc)))
   ansible-vault--header-options-regex-groups-alist
   :initial-value '()))

(defun ansible-vault--header-options--init-by-crypto-options (crypto-options)
  (cl-flet ((crypto-options (key) (a-get crypto-options key)))
    (ansible-vault--set-state
     :buffer :header-options
     (a-list :version (pcase (or (crypto-options :vault-encrypt-identity)
                                 (crypto-options :vault-identity-list))
                        (`nil "1.1")
                        (_    "1.2"))
             :cipher-algorithm "AES256"
             :vault-id (crypto-options :vault-encrypt-identity)))))

;; crypto-options is an a-list structure with parameters acceptable by ansible-vault tool

(defconst ansible-vault--crypto-options-keys
  '(:vault-password-file :vault-identity-list :vault-identity :vault-encrypt-identity :vault-id-match)
  "Keys available in crypto-options a-list structure.")

(defun ansible-vault--crypto-options-p (obj)
  (and (a-associative-p obj)
       (and (or (a-get obj :vault-password-file)
                (a-get obj :vault-identity-list))
            t)))

(defun ansible-vault--crypto-options--can-decrypt-1.1-p (obj)
  (and (a-associative-p obj)
       (a-get obj :vault-password-file)
       t))

(defun ansible-vault--crypto-options--can-encrypt-1.1-p (obj)
  (and (a-associative-p obj)
       (a-get obj :vault-password-file)
       t))

(defun ansible-vault--crypto-options--can-decrypt-1.2-p (obj)
  (and (a-associative-p obj)
       (a-get obj :vault-identity-list)
       t))

(defun ansible-vault--crypto-options--can-encrypt-1.2-p (obj)
  (and (a-associative-p obj)
       (a-get obj :vault-identity-list)
       (a-get obj :vault-encrypt-identity)
       t))

;; vault-id-list is a string that can be parsed to a-list of vault-ids and related password files

(defun ansible-vault--vault-id-list--parse (str &optional dir)
  (cl-loop for vault-id-pair-str in (split-string str ", ")
           for (vault-id vault-file) = (split-string vault-id-pair-str "@")
           when (and vault-id vault-file
                     (not (equal vault-file "prompt")))
           for vault-file = (if (and (f-relative vault-file) dir)
                                (expand-file-name vault-file dir)
                              vault-file)
           collect (cons vault-id vault-file)))

(defun ansible-vault--vault-id-list--to-string (vault-id-list)
  (cl-loop for (id . file) in vault-id-list
           collect (concat id "@" file) into ids
           finally return (mapconcat #'identity ids ", ")))

(defun ansible-vault--vault-id-list--get (vault-id-list vault-id)
  (a-get vault-id-list vault-id))

;; ──────────────────────────────────────────────────────────────
;; Buffer
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--buffer--get-first-line ()
  (save-excursion
    (goto-char (point-min))
    (string-trim-right (or (thing-at-point 'line t) ""))))  

(defun ansible-vault--buffer--encrypted-p ()
  (and (string-match ansible-vault--header-options-regex (ansible-vault--buffer--get-first-line)) t))

(defun ansible-vault--buffer--encrypted--init-header-options ()
  (let* ((first-line (ansible-vault--buffer--get-first-line))
         (header-options (ansible-vault--header-options--parse first-line)))
    (ansible-vault--set-state :buffer :header-options header-options)))

(defun ansible-vault--buffer--to-string ()
  (save-restriction
    (widen)
    (buffer-string)))

(defun ansible-vault--buffer--encrypted--decrypt ()
  (let* ((crypto-options (ansible-vault--get-state :ansible-cfg :crypto-options))
         (header-options (ansible-vault--get-state :buffer :header-options))
         (decrypted-str (ansible-vault--run :decrypt crypto-options header-options (ansible-vault--buffer--to-string))))
    (erase-buffer)
    (insert decrypted-str)
    (set-buffer-modified-p nil)
    (ansible-vault--set-state :buffer :encrypted nil)))
    
(defun ansible-vault--buffer--encrypt ()
  (if (buffer-modified-p)
      (let* ((crypto-options (ansible-vault--get-state :ansible-cfg :crypto-options))
             (header-options (ansible-vault--get-state :buffer :header-options))
             (encrypted-str (ansible-vault--run :encrypt crypto-options header-options
                                                (ansible-vault--buffer--to-string))))
        (erase-buffer)
        (insert encrypted-str)
        (set-buffer-modified-p nil))
    (revert-buffer nil t nil))
  (ansible-vault--set-state :buffer :encrypted t))

;; ──────────────────────────────────────────────────────────────
;; Misc
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--string-of-file (file)
  (with-temp-buffer
    (insert-file-contents file)
    (buffer-string)))

(defun ansible-vault--get-or-create-error-buffer ()
  "Generate or return `ansible-vault' error report buffer."
  (or (get-buffer "*ansible-vault-error*")
      (let ((buffer (get-buffer-create "*ansible-vault-error*")))
        (with-current-buffer buffer)
          (setq-local buffer-read-only t)
        buffer)))

;; ──────────────────────────────────────────────────────────────
;; Ansible.cfg
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--ansible-cfg--locate ()
  (cl-labels
      ((check-file (file) (when file (file-readable-p file)))
       (upward-search (from-path file) (expand-file-name file (locate-dominating-file from-path file))))
    (let* ((possible-sources (list (getenv "ANSIBLE_CONFIG")
                                   (upward-search buffer-file-name "ansible.cfg")
                                   "~/.ansible.cfg"
                                   "/etc/ansible/ansible.cfg"))
           (valid-sources (cl-remove-if-not #'check-file possible-sources)))
      (unless valid-sources (error "No ansible.cfg found"))
      (cl-first valid-sources))))

(defun ansible-vault--ansible-cfg--parse-key (key ansible-cfg-content)
  (let ((rx (rx line-start (literal key) (zero-or-more blank) "=" (zero-or-more blank)
                (group-n 1 (minimal-match (one-or-more not-newline)))
                (zero-or-more blank) (zero-or-more ";" (zero-or-more not-newline)) line-end)))
    (when (string-match rx ansible-cfg-content)
      (match-string 1 ansible-cfg-content))))
;; (ansible-vault--ansible-cfg--parse-key "vault_password_file" (ansible-vault--string-of-file "test/ansible.cfg"))

(defun ansible-vault--ansible-cfg--parse (ansible-cfg-content ansible-cfg-path)
  (let* ((ansible-cfg-options
          (a-list :vault-password-file "vault_password_file"
                  :vault-identity-list "vault_identity_list"
                  :vault-identity "vault_identity"
                  :vault-encrypt-identity "vault_encrypt_identity"
                  :vault-id-match "vault_id_match")))
    (cl-reduce
     (pcase-lambda (acc `(,key . ,cfgkey))
       (pcase (ansible-vault--ansible-cfg--parse-key cfgkey ansible-cfg-content)
         (str (pcase key
                (:vault-password-file
                 (a-assoc-in acc (list :vault-password-file)
                             (expand-file-name str (f-dirname ansible-cfg-path))))
                (:vault-identity-list
                 (let ((vault-id-list (ansible-vault--vault-id-list--parse str (f-dirname ansible-cfg-path))))
                   (a-assoc-in acc (list :vault-identity-list) vault-id-list)))
                (_ (a-assoc-in acc (list key) str))))
         (_     acc)))
     ansible-cfg-options
     :initial-value '())))
;; (ansible-vault--ansible-cfg--parse (ansible-vault--string-of-file "test/ansible.cfg") (f-full "test/ansible.cfg"))

(defun ansible-vault--ansible-cfg--init-crypto-options ()
  (let* ((ansible-cfg-path (ansible-vault--ansible-cfg--locate))
         (ansible-cfg-content (ansible-vault--string-of-file ansible-cfg-path))
         (ansible-cfg-parsed (ansible-vault--ansible-cfg--parse ansible-cfg-content ansible-cfg-path)))
    (ansible-vault--set-state :ansible-cfg :crypto-options ansible-cfg-parsed)
    (ansible-vault--set-state :ansible-cfg :path ansible-cfg-path)))

;; ──────────────────────────────────────────────────────────────
;; Shell
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--generate-shell-command (action crypto-options header-options)
  (let ((command (list ansible-vault-command)))
    (cl-labels ((header-options (key) (a-get header-options key))
                (crypto-options (key) (a-get crypto-options key))
                (cpush (elt) (push elt command)))
    (pcase action
      (:decrypt
       (cpush "decrypt")
       (cpush "--output=-")
       (pcase (header-options :version)
         ("1.1" (pcase (crypto-options :vault-password-file)
                  (`nil (error "Unknown vault-password-file"))
                  (val  (cpush "--vault-password-file")
                        (cpush val))))
         ("1.2" (pcase (crypto-options :vault-identity-list)
                  (`nil (error "Unknown vault-identity-list"))
                  (vidl (cl-loop for (id . file) in vidl
                                 do (progn (cpush "--vault-id")
                                           (cpush (concat id "@" file)))))))
         (ver   (error (format "Unknown ansible-vault crypto-header version: %s" ver)))))
      (:encrypt
       (cpush "encrypt")
       (cpush "--output=-")
       (pcase (header-options :version)
         ("1.1" (pcase (crypto-options :vault-password-file)
                  (`nil (error "Unknown vault-password-file"))
                  (val  (cpush "--vault-password-file")
                        (cpush val))))
         ("1.2" (let ((enc-id (or (header-options :vault-id)
                                  (crypto-options :vault-encrypt-identity))))
                  (unless enc-id
                    (error "Undefined vault-encrypt-identity"))
                  (cpush "--encrypt-vault-id")
                  (cpush enc-id)
                  (pcase (crypto-options :vault-identity-list)
                            (`nil (error "Unknown vault-identity-list"))
                            (vidl (cl-loop for (id . file) in vidl
                                           when (equal id enc-id)
                                           do (progn (cpush "--vault-id")
                                                     (cpush (concat id "@" file))))))))
         (ver (error (format "Unknown ansible-vault crypto-header version: %s" ver)))))
      (_ (error (format "Unknown action: %s" action))))
    (mapconcat #'identity (reverse command) " "))))

(defun ansible-vault--run (action crypto-options header-options str)
  ""
  (let ((command (ansible-vault--generate-shell-command action crypto-options header-options))
        (cmd-buf-stdout (generate-new-buffer "ansible-vault-cmd-stdout"))
        (cmd-buf-stderr (generate-new-buffer "ansible-vault-cmd-stderr"))
        (env-ansible-vault-password-file (getenv "ANSIBLE_VAULT_PASSWORD_FILE")))
    ;;(message command)
    (unwind-protect
        (pcase (unwind-protect
                   (progn
                     (when env-ansible-vault-password-file
                       (setenv "ANSIBLE_VAULT_PASSWORD_FILE" nil))
                     (with-temp-buffer
                       (insert str)
                       (let ((inhibit-message t) ; disable output to *Messages* from elisp `message' function
                             (message-log-max nil) ; disable output to *Messages* from c-code
                             ;; run ansible-vault somewhere ansible.cfg 100% not present
                             (default-directory temporary-file-directory))
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
      )))

;; ──────────────────────────────────────────────────────────────
;; Keymap
;; ──────────────────────────────────────────────────────────────

(defvar ansible-vault-mode-map
  (cl-flet ((genkey (chord) (kbd (concat ansible-vault-minor-mode-prefix " " chord))))
    (let ((map (make-sparse-keymap)))
      (define-key map (genkey "d") 'ansible-vault-decrypt-current-buffer)
;;      (define-key map (genkey "D") 'ansible-vault-decrypt-region)
      (define-key map (genkey "e") 'ansible-vault-encrypt-current-buffer)
;;      (define-key map (genkey "E") 'ansible-vault-encrypt-region)
;;      (define-key map (genkey "p") 'ansible-vault--request-password)
;;      (define-key map (genkey "i") 'ansible-vault--request-vault-id)
      map))
  "Keymap for `ansible-vault' minor mode.")


;; ──────────────────────────────────────────────────────────────
;; Interactive functions
;; ──────────────────────────────────────────────────────────────

;; the main difference between interactive functions and internal functions is in the suggestion
;; that internal functions suppose to get valid arguments all the time (as it's me who calls it)

;; on the other hand interactive functions can be called by user, so they must have all the possible
;; checks in order to ensure we can call appropriate internal functions

(defun ansible-vault-decrypt-current-buffer ()
  "In place decryption of `current-buffer' using `ansible-vault'."
  (interactive)
  (unless (ansible-vault--get-state :buffer :encrypted)
    (user-error "Cannot decrypt unencrypted buffer"))
  (let ((crypto-options (ansible-vault--get-state :ansible-cfg :crypto-options))
        (header-options (ansible-vault--get-state :buffer :header-options)))
    (pcase (a-get header-options :version)
      ("1.1" (unless (ansible-vault--crypto-options--can-decrypt-1.1-p crypto-options)
               (user-error "Cannot decrypt (vault header v1.1), check if vault_password_file provided")))
      ("1.2" (unless (ansible-vault--crypto-options--can-decrypt-1.2-p crypto-options)
               (user-error "Cannot decrypt (vault header v1.2), check if vault_identity_list provided")))
      (ver   (user-error "Cannot decrypt due to unknown vault header version: %s" ver)))
    (ansible-vault--buffer--encrypted--decrypt)))

(defun ansible-vault-encrypt-current-buffer ()
  "In place encryption of `current-buffer' using `ansible-vault'."
  (interactive)
  (when (ansible-vault--get-state :buffer :encrypted)
    (user-error "Cannot encrypt encrypted buffer"))
  (let ((crypto-options (ansible-vault--get-state :ansible-cfg :crypto-options)))
    (pcase (a-get crypto-options :vault-encrypt-identity)
      (`nil   (unless (a-get crypto-options :vault-password-file)
                (user-error "Cannot encrypt: neither vault_encrypt_identity nor vault_password_file provided")))
      (enc-id (unless (a-get crypto-options :vault-identity-list enc-id)
                (user-error "Cannot encrypt: encryption vault id `%s' not found" enc-id))))
    (ansible-vault--buffer--encrypt)))


;; ──────────────────────────────────────────────────────────────
;; Integration with hooks
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--before-save ()
  (unless (ansible-vault--get-state :buffer :encrypted)
    (ansible-vault--set-state :restore-point (point))
    (ansible-vault--buffer--encrypt)
    ))

(defun ansible-vault--after-save ()
  (when (ansible-vault--get-state :buffer :encrypted)
    (ansible-vault--buffer--encrypted--decrypt)
    (set-buffer-modified-p nil)
    (goto-char (ansible-vault--get-state :restore-point))
    (ansible-vault--set-state :restore-point nil)
    ))

;; ──────────────────────────────────────────────────────────────
;; Mode
;; ──────────────────────────────────────────────────────────────

;; functions of mode enabling/disabling are considered as interactive too

(defun ansible-vault-mode-enable ()
  "Enable `ansible-vault-mode'"
  (interactive)

  ;; disable backups and auto-save
  (setq-local backup-inhibited t)
  (when auto-save-default (auto-save-mode -1))

  ;; initialize state
  (unless (ansible-vault--get-state :mode :initialized)
    (ansible-vault--set-state :buffer :initially-encrypted (ansible-vault--buffer--encrypted-p))
    ;; different initialization for encrypted and unencrypted buffers
    (pcase (ansible-vault--get-state :buffer :initially-encrypted)
      (`nil (ansible-vault--set-state :buffer :encrypted nil)
            (ansible-vault--ansible-cfg--init-crypto-options)
            (ansible-vault--header-options--init-by-crypto-options
             (ansible-vault--get-state :ansible-cfg :crypto-options))
            )
      (`t   (ansible-vault--set-state :buffer :encrypted t)
            (ansible-vault--buffer--encrypted--init-header-options)
            (ansible-vault--ansible-cfg--init-crypto-options)
            ))
    (ansible-vault--set-state :mode :initialized t))

  ;; automatically decrypt buffer if needed
  (when (and (ansible-vault--get-state :buffer :encrypted)
             ansible-vault-auto-decrypt)
    (ansible-vault-decrypt-current-buffer))
  
  ;; add hooks
  (add-hook 'before-save-hook 'ansible-vault--before-save t t)
  (put 'before-save-hook 'permanent-local t)
  (add-hook 'after-save-hook 'ansible-vault--after-save t t)
  (put 'after-save-hook 'permanent-local t)
    
  ;; optionally run major mode switch in order to enable some appropriate mode by
  ;; magic-mode-alist using unencrypted buffer content
  (when (and ansible-vault-auto-determine-major-mode-by-decrypted-content
             (ansible-vault--get-state :buffer :initially-encrypted)
             (not (ansible-vault--get-state :buffer :encrypted)))
    (normal-mode))
  )

(defun ansible-vault-mode-disable ()
  "Disable `anasible-vault-mode'"
  (interactive)
  (when (ansible-vault--get-state :buffer :initially-encrypted)
    (when (and (buffer-modified-p)
             (ansible-vault--get-state :buffer :encrypted))
      (ansible-vault-encrypt-current-buffer))))

;;;###autoload
(define-minor-mode ansible-vault-mode
  "Minor mode for manipulating ansible-vault files"
  :lighter " ansible-vault"
  :keymap ansible-vault-mode-map
  :group 'ansible-vault

  (if ansible-vault-mode
      (ansible-vault-mode-enable)
    (ansible-vault-mode-disable)))

(put 'ansible-vault-mode 'permanent-local t)

;; ──────────────────────────────────────────────────────────────
;; Optional Integrations
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault-mode-enable-by-magic ()
  (add-to-list 'auto-minor-mode-magic-alist
               (cons #'ansible-vault--buffer--encrypted-p #'ansible-vault-mode)))

(with-eval-after-load 'auto-minor-mode
  (when ansible-vault-mode-enable-by-magic
    (ansible-vault-mode-enable-by-magic)))

;; ──────────────────────────────────────────────────────────────
;; Obsolete aliases
;; ──────────────────────────────────────────────────────────────

;; none at the moment
;; define-obsolete-variable-alias and so on will be here

;; ──────────────────────────────────────────────────────────────
;; Footer
;; ──────────────────────────────────────────────────────────────

(provide 'ansible-vault)

;;; ansible-vault.el ends here
