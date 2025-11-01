;;; ansible-vault.el --- Minor mode for editing ansible vault files -*- lexical-binding: t; -*-

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
;; No comments

;;; License:

;; This program is free software; you can redistribute it and/or modify it
;; under the terms of the GNU General Public License as published by the Free
;; Software Foundation; either version 3 of the License, or (at your option)
;; any later version.

;; This program is distributed in the hope that it will be useful, but WITHOUT
;; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
;; FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
;; more details.

;; You should have received a copy of the GNU General Public License along
;; with GNU Emacs; see the file COPYING.  If not, write to the Free Software
;; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
;; USA.

;;; Code:

;; ──────────────────────────────────────────────────────────────
;; Ansible Documentation Snippets
;; ──────────────────────────────────────────────────────────────

;; ansible-vault variables
;; https://docs.ansible.com/ansible/latest/reference_appendices/config.html

;; DEFAULT_VAULT_PASSWORD_FILE
;; [defaults] vault_password_file None
;; 
;; The vault password file to use. Equivalent to --vault-password-file or --vault-id. If executable,
;; it will be run and the resulting stdout will be used as the password.

;; DEFAULT_VAULT_IDENTITY_LIST
;; [defaults] vault_identity_list []
;; 
;; A list of vault-ids to use by default. Equivalent to multiple --vault-id args. Vault-ids are
;; tried in order.

;; DEFAULT_VAULT_IDENTITY
;; [defaults] vault_identity default
;; 
;; The label to use for the default vault id label in cases where a vault id label is not provided.

;; DEFAULT_VAULT_ENCRYPT_IDENTITY
;; [defaults] vault_encrypt_identity
;; 
;; The vault_id to use for encrypting by default. If multiple vault_ids are provided, this specifies
;; which to use for encryption. The --encrypt-vault-id CLI option overrides the configured value.

;; DEFAULT_VAULT_ID_MATCH
;; [defaults] vault_id_match false
;; 
;; If true, decrypting vaults with a vault id will only try the password from the matching vault-id.




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


;; ──────────────────────────────────────────────────────────────
;; Internal variables
;; ──────────────────────────────────────────────────────────────

(defvar ansible-vault--vault-header-regex
  (rx line-start "$ANSIBLE_VAULT;"
      (group-n 1 "1." (any "12")) ";"
      (group-n 2 "AES" (optional "256"))
      (optional ";" (group-n 3 (+ any)))
      line-end)
  "Regex for `ansible-vault' header for identifying of encrypted buffers.")

(defvar ansible-vault--vault-header-regex-groups-alist
  (a-list :version 1
          :cipher-algorithm 2
          :vault-id 3))

;; ──────────────────────────────────────────────────────────────
;; Local variables
;; ──────────────────────────────────────────────────────────────

(defvar ansible-vault--state '())
(make-variable-buffer-local 'ansible-vault--state)
(put 'ansible-vault--state 'permanent-local t)

;; ──────────────────────────────────────────────────────────────
;; Core
;; ──────────────────────────────────────────────────────────────

;; internal state functions

(defun ansible-vault--get-state (&rest keys)
  (a-get-in ansible-vault--state keys))

(defun ansible-vault--set-state (&rest keys-and-newval)
  (let ((keys (butlast keys-and-newval))
        (newval (car (reverse keys-and-newval))))
    (setq-local ansible-vault--state
                (a-assoc-in ansible-vault--state keys newval))))

;; header functions

(defun ansible-vault--parse-vault-header (header)
  "Takes ansible vault HEADER and parse it, returning alist.

If HEADER is \"$ANSIBLE_VAULT;1.2;AES256;prod\" it will return
\((:vault-id . \"prod\")
 (:cipher-algorithm . \"AES256\")
 (:version . \"1.2\"))"
  (unless (string-match ansible-vault--vault-header-regex header)
    (error (format "Not an ansible-vault header: %s" header)))
  (cl-reduce
   (pcase-lambda (acc `(,key . ,n))
     (pcase (match-string n header)
       ((and val (guard val))  (a-assoc-in acc (list key) val))
       (_                      acc)))
   ansible-vault--vault-header-regex-groups-alist
   :initial-value '()))

;; buffer analysis

(defun ansible-vault--get-first-buffer-line ()
  (save-excursion
    (goto-char (point-min))
    (string-trim-right (or (thing-at-point 'line t) ""))))  

(defun ansible-vault--encrypted-buffer--init-state-header ()
  (let* ((first-line (ansible-vault--get-first-buffer-line))
         (parsed-header (ansible-vault--parse-vault-header first-line)))
    (ansible-vault--set-state :buffer-header parsed-header)))

(defun ansible-vault--is-buffer-encrypted ()
  (and (string-match ansible-vault--vault-header-regex (ansible-vault--get-first-buffer-line)) t))

;; ansible.cfg functions

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

(defun ansible-vault--string-of-file (file)
  (with-temp-buffer
    (insert-file-contents file)
    (buffer-string)))
;; (ansible-vault--string-of-file "test/ansible.cfg")

(defun ansible-vault--ansible-cfg--parse-key (key ansible-cfg-content)
  (let ((rx (rx line-start (literal key) (zero-or-more blank) "=" (zero-or-more blank)
                (group-n 1 (minimal-match (one-or-more not-newline)))
                (zero-or-more blank) (zero-or-more ";" (zero-or-more not-newline)) line-end)))
    (when (string-match rx ansible-cfg-content)
      (match-string 1 ansible-cfg-content))))
;; (ansible-vault--ansible-cfg--parse-key "vault_password_file" (ansible-vault--string-of-file "test/ansible.cfg"))

(defun ansible-vault--ansible-cfg--parse (ansible-cfg-content)
  (let ((ansible-cfg-options (a-list :vault-password-file "vault_password_file"
                                     :vault-identity-list "vault_identity_list"
                                     :vault-identity "vault_identity"
                                     :vault-encrypt-identity "vault_encrypt_identity"
                                     :vault-id-match "vault_id_match")))
    (cl-reduce
     (pcase-lambda (acc `(,key . ,cfgkey))
       (pcase (ansible-vault--ansible-cfg--parse-key cfgkey ansible-cfg-content)
         ((and val (guard val))   (a-assoc-in acc (list key) val))
         (_                       acc)))
     ansible-cfg-options
     :initial-value '())))
;; (ansible-vault--ansible-cfg--parse (ansible-vault--string-of-file "test/ansible.cfg"))

(defun ansible-vault--init-state-ansible-cfg ()
  (let* ((ansible-cfg-path (ansible-vault--ansible-cfg--locate))
         (ansible-cfg-content (ansible-vault--string-of-file ansible-cfg-path))
         (ansible-cfg-parsed (ansible-vault--ansible-cfg--parse ansible-cfg-content)))
    (ansible-vault--set-state :ansible-cfg :crypto-options ansible-cfg-parsed)
    (ansible-vault--set-state :ansible-cfg :path ansible-cfg-path)))


;; ──────────────────────────────────────────────────────────────
;; ansible-vault cli handling
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--generate-shell-command (action crypto-options header-options)
  (let ((command (list ansible-vault-command)))
    (cl-labels ((header-options (&rest keys) (a-get-in header-options keys))
                (crypto-options (&rest keys) (a-get-in crypto-options keys))
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
                  (str  (cl-loop for vault-id in (split-string str ", ")
                                 do (cpush "--vault-id")
                                 do (cpush vault-id)))))
         (ver   (error (format "Unknown ansible-vault crypto-header version: %s" ver)))))
      (_ (error (format "Unknown action: %s" action))))
    (mapconcat #'identity (reverse command) " ")
    )))

(defun ansible-vault--get-or-create-error-buffer ()
  "Generate or return `ansible-vault' error report buffer."
  (or (get-buffer "*ansible-vault-error*")
      (let ((buffer (get-buffer-create "*ansible-vault-error*")))
        (with-current-buffer buffer)
          (setq-local buffer-read-only t)
        buffer)))

(defun ansible-vault--run (action crypto-options header-options str)
  (let ((command (ansible-vault--generate-shell-command action crypto-options header-options))
        (cmd-buf-stdout (generate-new-buffer "ansible-vault-cmd-stdout"))
        (cmd-buf-stderr (generate-new-buffer "ansible-vault-cmd-stderr"))
        (env-ansible-vault-password-file (getenv "ANSIBLE_VAULT_PASSWORD_FILE")))
    (unwind-protect
        (pcase (unwind-protect
                   (progn
                     (when env-ansible-vault-password-file
                       (setenv "ANSIBLE_VAULT_PASSWORD_FILE" nil))
                     (with-temp-buffer
                       (insert str)
                       (message "xxx")
                       (message (buffer-string))
                       (message command)
                       (let ((start (point-min))
                             (end (point-max)))
                         (message (format "yyy: %d %d" start end))
                         (shell-command-on-region (point-min) (point-max)
                                                  command
                                                  cmd-buf-stdout nil
                                                  cmd-buf-stderr nil))))
                 (when env-ansible-vault-password-file
                   (setenv "ANSIBLE_VAULT_PASSWORD_FILE" env-ansible-vault-password-file)))
          (0 (with-current-buffer cmd-buf-stdout
               (message (buffer-name cmd-buf-stdout))
               (message (buffer-name cmd-buf-stderr))
               (message "zzz")
               (message (buffer-string))
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


      
        
            
              
           














;;
;;
;;;; shell command generation
;;
;;(defun ansible-vault--sub-command-type (sub-command)
;;  "Identify type of ansible-vault subcommand for cli tool flags generation.
;;
;;SUB-COMMAND ansible-vault cli sub-command to type."
;;  (cdr (assoc sub-command ansible-vault--sub-command-type-alist)))
;;
;;(defun ansible-vault--command-flags (sub-command)
;;  "Generate the command flags for calling `ansible-vault'.
;;
;;SUB-COMMAND the sub-command of ansible vault as a string.  Valid
;;values can be found in `ansible-vault--sub-command-type-alist'."
;;  (let* ((type (ansible-vault--sub-command-type sub-command))
;;         (v1.2-p (or (string= ansible-vault--header-version "1.2")
;;                     ansible-vault--header-vault-id
;;                     ansible-vault--vault-id)))
;;    (append
;;     '("--output=-")
;;     (if v1.2-p
;;         (let* ((vault-id-pair (assoc ansible-vault--vault-id ansible-vault-vault-id-alist))
;;                (vault-id-str (concat (car vault-id-pair) "@" (cdr vault-id-pair))))
;;           (list
;;            (format "--vault-id=%S" vault-id-str)
;;            (when (eq type :encrypt) (format "--encrypt-vault-id=%S" ansible-vault--vault-id))))
;;       (list (format "--vault-password-file=%S" ansible-vault--password-file))))
;;    ))
;;
;;(defun ansible-vault--shell-command (sub-command)
;;  "Generate Ansible Vault shell call for SUB-COMMAND.
;;
;;The command \"ansible-vault\" flags are generated via the
;;`ansible-vault--command-flags' function.  The flag values are
;;dictated by the buffer local variables.
;;
;;SUB-COMMAND is the \"ansible-vault\" subcommand to use."
;;  (let* ((command-flags (ansible-vault--command-flags sub-command)))
;;    (format "%s %s %s" ansible-vault-command sub-command
;;            (mapconcat 'identity command-flags " "))))
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
;;;; setting local variables and creating necessary files
;;
;;(defun ansible-vault--create-password-file (password)
;;  "Generate a temporary file to store PASSWORD.
;;
;;The generated file is located in TMPDIR, and is marked read-only
;;for owner."
;;  (let* ((temp-file (make-temp-file "ansible-vault-secret-")))
;;    (set-file-modes temp-file #o0600)
;;    (append-to-file password nil temp-file)
;;    (set-file-modes temp-file #o0400)
;;    (setq-local ansible-vault--password-file temp-file)
;;    (push ansible-vault--password-file ansible-vault--password-file-list)
;;    temp-file))
;;
;;(defun ansible-vault--request-password (password)
;;  "Prompt user a for the password for the current buffer.
;;
;;PASSWORD ansible-vault password to be stored."
;;  (interactive
;;   (list (read-passwd "Vault Password: ")))
;;  (ansible-vault--create-password-file password))
;;
;;(defun ansible-vault--request-vault-id (vault-id &optional password-file)
;;  "Prompt user for a vault-id for the current buffer.
;;
;;If the vault-id doesn't have an associated password file, request
;;a password from the user as well.
;;
;;VAULT-ID ansible-vault vault id.
;;PASSWORD-FILE path to the stored secret for provided VAULT-ID."
;;  (interactive "Vault Id: ")
;;  (let* ((vault-id-pair
;;          (or (assoc vault-id ansible-vault-vault-id-alist)
;;              (let* ((password-file (or password-file
;;                                        (call-interactively 'ansible-vault--request-password))))
;;                (car (push (cons vault-id password-file) ansible-vault-vault-id-alist)))))
;;         (password-file (or password-file (cdr vault-id-pair))))
;;    (setq-local ansible-vault--vault-id vault-id)
;;    (setq-local ansible-vault--password-file password-file)
;;    vault-id-pair))
;;
;;;; side-effect: it sets ansible-vault--password-file
;;(defun ansible-vault--guess-password-file ()
;;  "Attempts to determine the correct ansible-vault password file.
;;
;;Ansible vault has several locations to store the configuration of
;;its password file."
;;  (interactive)
;;  (when (not ansible-vault--password-file)
;;    (let* ((env-val (or (getenv "ANSIBLE_VAULT_PASSWORD_FILE") ""))
;;           (vault-id-pair (assoc ansible-vault--header-vault-id ansible-vault-vault-id-alist))
;;           (ansible-config-path (ansible-vault--process-config-files)))
;;      (cond
;;       (vault-id-pair
;;        (setq-local ansible-vault--vault-id (car vault-id-pair))
;;        (setq-local ansible-vault--password-file (cdr vault-id-pair)))
;;       (ansible-vault--header-vault-id
;;        (ansible-vault--request-vault-id ansible-vault--header-vault-id))
;;       (t (let* ((password-file
;;                  (or (and (not (string-empty-p env-val)) env-val)
;;                      ansible-config-path
;;                      ansible-vault-password-file)))
;;            (setq-local
;;             ansible-vault--password-file password-file))))
;;      ))
;;  (when (not (and ansible-vault--password-file (file-readable-p ansible-vault--password-file)))
;;    (let* ((vault-id (or ansible-vault--header-vault-id ansible-vault--vault-id)))
;;      (cond (vault-id (ansible-vault--request-vault-id vault-id))
;;            (t (call-interactively 'ansible-vault--request-password)))
;;      ))
;;  ansible-vault--password-file)
;;
;;;; unsetting variables and deleting unnecessary files
;;
;;(defun ansible-vault--flush-password-file ()
;;  "Delete password file and associated buffer local variables."
;;  (when ansible-vault--password-file
;;    (when (member ansible-vault--password-file ansible-vault--password-file-list)
;;      (setq ansible-vault--password-file-list
;;            (remove ansible-vault--password-file ansible-vault--password-file-list))
;;      (delete-file ansible-vault--password-file))
;;    (setq-local ansible-vault--password-file nil)))
;;
;;(defun ansible-vault--flush-vault-id ()
;;  "Delete vault-id pair and associated buffer local variables."
;;  (when ansible-vault--vault-id
;;    (when (map-contains-key ansible-vault-vault-id-alist ansible-vault--vault-id)
;;      (setq ansible-vault-vault-id-alist
;;            (map-filter (lambda (key _)
;;                          (not (string= key ansible-vault--vault-id)))
;;                        ansible-vault-vault-id-alist)))
;;    (setq-local ansible-vault--vault-id nil)
;;    (ansible-vault--flush-password-file)))
;;
;;(defun ansible-vault--cleanup-password-error ()
;;  "Flush both vault and password values."
;;  (when ansible-vault--vault-id
;;    (ansible-vault--flush-vault-id))
;;  (when ansible-vault--password-file
;;    (ansible-vault--flush-password-file)))
;;
;;(defun ansible-vault--clear-local-variables ()
;;  "Unset all buffer local variables."
;;  (dolist (var '(ansible-vault--header-version
;;                 ansible-vault--header-cipher-algorithm
;;                 ansible-vault--header-vault-id
;;                 ansible-vault--point
;;                 ansible-vault--password-file
;;                 ansible-vault--vault-id
;;                 ansible-vault--auto-encryption-enabled))
;;    (makunbound var)))
;;
;;;; error handling
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
;;
;;
;;
;;
;;
;;;; run ansible-vault cli tool
;;
;;(defun ansible-vault--execute-on-region (command &optional start end buffer error-buffer)
;;  "In place execution of a given COMMAND using `ansible-vault'.
;;
;;START defaults to `point-min'.
;;END defaults to `point-max'.
;;BUFFER defaults to current buffer.
;;ERROR-BUFFER defaults to `ansible-vault--error-buffer'."
;;  (message "execute 1")
;;  (message "execute 1.1")
;;  (save-excursion
;;    (widen) ;; if we're in narrowed buffer, point-max will be less than 1+ buffer-size
;;    (let* (;; Silence messages
;;           (inhibit-message nil)
;;           (message-log-max 1000)
;;           (_ (message "x1"))
;;           ;; Set default arguments
;;           (start (or start (point-min)))
;;           (_ (message "x2"))
;;           (end (or end (point-max)))
;;           (_ (message "x3"))
;;           (error-buffer (or error-buffer (ansible-vault--error-buffer)))
;;           (_ (message "x4"))
;;  
;;           ;; Local variables
;;           (ansible-vault-stdout (get-buffer-create "*ansible-vault-stdout*"))
;;           (ansible-vault-stderr (get-buffer-create "*ansible-vault-stderr*")))
;;      (message "execute 2")
;;      (ansible-vault--guess-password-file)
;;      (message "execute 3")
;;      (unwind-protect
;;          (progn
;;            (let ((shell-command (ansible-vault--shell-command command)))
;;              (let ((env-ansible-vault-password-file (getenv "ANSIBLE_VAULT_PASSWORD_FILE")))
;;                (unwind-protect
;;                    (progn
;;                      (setenv "ANSIBLE_VAULT_PASSWORD_FILE" nil)
;;                      (message (format "start %d end %d" start end))
;;                      (message (format "bufsize %d" (buffer-size)))
;;                      (shell-command-on-region start end shell-command
;;                                               ansible-vault-stdout nil
;;                                               ansible-vault-stderr nil))
;;                  (setenv "ANSIBLE_VAULT_PASSWORD_FILE" env-ansible-vault-password-file)))
;;              (if (zerop (buffer-size ansible-vault-stderr))
;;                  (progn
;;                    (delete-region start end)
;;                    (insert-buffer-substring ansible-vault-stdout))
;;                (let ((inhibit-read-only t))
;;                  (switch-to-buffer error-buffer)
;;                  (goto-char (point-max))
;;                  (insert "$ " shell-command "\n")
;;                  (insert-buffer-substring ansible-vault-stderr)
;;                  (insert "\n")
;;                  (ansible-vault--cleanup-password-error)))
;;              ))
;;        (kill-buffer ansible-vault-stdout)
;;        (kill-buffer ansible-vault-stderr))
;;      )))
;;
;;;; interactive actions
;;(defun ansible-vault-decrypt-current-buffer ()
;;  "In place decryption of `current-buffer' using `ansible-vault'."
;;  (interactive)
;;  (message "decrypt 1")
;;  (ansible-vault--execute-on-region "decrypt"))
;;
;;(defun ansible-vault-decrypt-current-file ()
;;  "Decrypts the current buffer and writes the file."
;;  (interactive)
;;  (setq-local ansible-vault--auto-encryption-enabled nil)
;;  (ansible-vault-decrypt-current-buffer)
;;  (save-buffer 0))
;;
;;(defun ansible-vault-encrypt-current-buffer ()
;;  "In place encryption of `current-buffer' using `ansible-vault'."
;;  (interactive)
;;  (ansible-vault--execute-on-region "encrypt"))
;;
;;(defun ansible-vault-encrypt-current-file ()
;;  "Encrypts the current buffer and writes the file."
;;  (interactive)
;;  (setq-local ansible-vault--auto-encryption-enabled t)
;;  (set-buffer-modified-p t)
;;  (save-buffer 0)
;;  (ansible-vault--fingerprint-buffer))
;;
;;(defun ansible-vault-decrypt-region (start end)
;;  "In place decryption of region from START to END using `ansible-vault'."
;;  (interactive "r")
;;  (let ((inhibit-read-only t))
;;    ;; Restrict the following operations to the selected region.
;;    (narrow-to-region start end)
;;    (goto-char (point-min))
;;    ;; Delete header and save non-vault values
;;    (let* ((first-line (thing-at-point 'line t))
;;           (match-data (string-match (rx line-start (group (zero-or-more any)) "!vault |" line-end) first-line))
;;           (header (match-string 1 first-line)))
;;      ;; remove header if it exists
;;      (when (and match-data (zerop match-data))
;;        (kill-whole-line))
;;      ;; realign encrypted data
;;      (goto-char (point-min))
;;      (let* ((line-count 0))
;;        (while (zerop line-count)
;;          (delete-horizontal-space)
;;          (setq
;;           line-count (forward-line))))
;;      ;; fingerprint new buffer
;;      (ansible-vault--fingerprint-buffer)
;;      ;; decrypt region
;;      (ansible-vault-decrypt-current-buffer)
;;      ;; replace header
;;      (when header
;;        (goto-char (point-min))
;;        (insert header)))
;;    ;; show the whole buffer again
;;    (widen)))
;;
;;(defun ansible-vault-encrypt-region (start end)
;;  "In place encryption of region from START to END using `ansible-vault'."
;;  (interactive "r")
;;  (ansible-vault--execute-on-region "encrypt_string" start end))
;;
;;;; key mapping
;;
;;(defun ansible-vault--chord (chord)
;;  "Key sequence generator for ansible-vault minor mode.
;;
;;CHORD is the trailing key sequence to append ot the mode prefix."
;;  (kbd (concat ansible-vault-minor-mode-prefix " " chord)))
;;
;;(defvar ansible-vault-mode-map
;;  (let ((map (make-sparse-keymap)))
;;    (define-key map (ansible-vault--chord "d") 'ansible-vault-decrypt-current-file)
;;    (define-key map (ansible-vault--chord "D") 'ansible-vault-decrypt-region)
;;    (define-key map (ansible-vault--chord "e") 'ansible-vault-encrypt-current-file)
;;    (define-key map (ansible-vault--chord "E") 'ansible-vault-encrypt-region)
;;    (define-key map (ansible-vault--chord "p") 'ansible-vault--request-password)
;;    (define-key map (ansible-vault--chord "i") 'ansible-vault--request-vault-id)
;;    map)
;;  "Keymap for `ansible-vault' minor mode.")
;;
;;;; hooks
;;
;;(defun ansible-vault--before-save-hook ()
;;  "`before-save-hook' for files managed by `ansible-vault-mode'.
;;
;;Saves the current position and encrypts the file before writing
;;to disk."
;;;  (save-excursion
;;;    (widen)
;;    (when (and ansible-vault--auto-encryption-enabled
;;               (not (ansible-vault--is-encrypted-vault-file)))
;;      (setq-local ansible-vault--point (point))
;;      (ansible-vault-encrypt-current-buffer)));)
;;
;;(defun ansible-vault--after-save-hook ()
;;  "`after-save-hook' for files managed by `ansible-vault-mode'.
;;
;;Decrypts the file, and returns the point to the position saved by
;;the `before-save-hook'."
;;;  (save-excursion
;;;    (widen)
;;    (when (and ansible-vault--auto-encryption-enabled
;;               (ansible-vault--is-encrypted-vault-file))
;;      (ansible-vault-decrypt-current-buffer)
;;      (set-buffer-modified-p nil)
;;      (goto-char ansible-vault--point)
;;      (setq-local ansible-vault--point 0)));)
;;
;;(defun ansible-vault--kill-buffer-hook ()
;;  "`kill-buffer-hook' for buffers managed by `ansible-vault-mode'.
;;
;;Flushes saved password state."
;;  (when ansible-vault--vault-id
;;    (ansible-vault--flush-vault-id))
;;  (when ansible-vault--password-file
;;    (ansible-vault--flush-password-file)))
;;
;;;;;###autoload
;;(defun ansible-vault--kill-emacs-hook ()
;;  "`kill-emacs-hook' for Emacs when `ansible-vault-mode' is loaded.
;;
;;Ensures deletion of ansible-vault generated password files."
;;  (dolist (file ansible-vault--password-file-list)
;;    (when (file-readable-p file)
;;      (delete-file file))
;;    ))
;;
;;;; ──────────────────────────────────────────────────────────────
;;;; Mode
;;;; ──────────────────────────────────────────────────────────────
;;
;;;;;###autoload
;;(define-minor-mode ansible-vault-mode
;;  "Minor mode for manipulating ansible-vault files"
;;  :lighter " ansible-vault"
;;  :keymap ansible-vault-mode-map
;;  :group 'ansible-vault
;;
;;  (if ansible-vault-mode
;;      ;; Enable the mode
;;      (progn
;;        (message "enable")
;;
;;        ;; Disable backups
;;        (setq-local
;;         backup-inhibited t)
;;        (message "enable 1")
;;        ;; Disable auto-save
;;        (when auto-save-default
;;          (auto-save-mode -1))
;;        (message "enable 2")
;;        ;; Decrypt the current buffer first if it needs to be
;;        (when (ansible-vault--is-encrypted-vault-file)
;;          (message "enable 3")
;;          (setq-local ansible-vault--auto-encryption-enabled t)
;;          (message "enable 4")
;;          (ansible-vault--fingerprint-buffer)
;;          (message "enable 5")
;;          (ansible-vault-decrypt-current-buffer)
;;          (message "enable 6")
;;          (set-buffer-modified-p nil))
;;        
;;        ;; Add mode hooks
;;        (message "enable 7")
;;        (add-hook 'before-save-hook 'ansible-vault--before-save-hook t t)
;;        (add-hook 'after-save-hook 'ansible-vault--after-save-hook t t)
;;        (add-hook 'kill-buffer-hook 'ansible-vault--kill-buffer-hook t t)
;;
;;        ;; make hooks resistant to kill-all-local-variables
;;        (put 'before-save-hook 'permanent-local t)
;;        (put 'after-save-hook 'permanent-local t)
;;        (put 'kill-buffer-hook 'permanent-local t)
;;
;;        (message "enable 8")
;;        ;; change major mode
;;        ;(normal-mode)
;;        )
;;
;;    (message "disable")
;;    
;;    ;; Disable the mode
;;    (remove-hook 'after-save-hook 'ansible-vault--after-save-hook t)
;;    (remove-hook 'before-save-hook 'ansible-vault--before-save-hook t)
;;    (remove-hook 'kill-buffer-hook 'ansible-vault--kill-buffer-hook t)
;;
;;    ;; Only re-encrypt the buffer if buffer is changed; otherwise revert
;;    ;; to on-disk contents.
;;    (if (and (buffer-modified-p) (not (ansible-vault--is-encrypted-vault-file)))
;;        (ansible-vault-encrypt-current-buffer)
;;      (revert-buffer nil t nil))
;;    ;; revert-buffer calls normal-mode
;;    ;; normal-mode calls set-auto-mode
;;    ;; set-auto-mode looks into magic-mode-alist
;;    ;; and I have added ansible-vault-mode to magic-mode-alist!!!
;;    ;; so it will be enabled here back
;;
;;    ;; Clean up password state
;;    (ansible-vault--flush-password-file)
;;    (ansible-vault--flush-vault-id)
;;
;;    (if auto-save-default (auto-save-mode 1))
;;
;;    (setq-local
;;     backup-inhibited nil)
;;
;;    (ansible-vault--clear-local-variables)))
;;
;;;; make the mode undescructable
;;
;;(put 'ansible-vault-mode 'permanent-local t)
;;
;;;; ──────────────────────────────────────────────────────────────
;;;; Integrations
;;;; ──────────────────────────────────────────────────────────────
;;
;;;(add-to-list 'auto-minor-mode-magic-alist
;;;             (cons #'ansible-vault--is-encrypted-vault-file #'ansible-vault-mode))
;;
;;;; ──────────────────────────────────────────────────────────────
;;;; Obsolete aliases (explicit!)
;;;; ──────────────────────────────────────────────────────────────
;;
;;(define-obsolete-variable-alias
;;  'ansible-vault-pass-file 'ansible-vault-password-file "0.4.0"
;;  "Migrated to unify naming conventions.")
;;
;;(define-obsolete-variable-alias
;;  'ansible-vault--is-vault-file 'ansible-vault--is-encrypted-vault-file "0.4.2"
;;  "Renamed for semantic correctness.")
;;
;;(define-obsolete-variable-alias
;;  'ansible-vault--flush-password 'ansible-vault--flush-password-file "0.4.2"
;;  "Renamed for semantic correctness.")
;;
;;;; ──────────────────────────────────────────────────────────────
;;;; Footer
;;;; ──────────────────────────────────────────────────────────────
;;
;;(provide 'ansible-vault)
;;
;;;;; ansible-vault.el ends here
;;
