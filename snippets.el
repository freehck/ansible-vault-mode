;; ──────────────────────────────────────────────────────────────
;; Can be useful later
;; ──────────────────────────────────────────────────────────────

(defun ansible-vault--request-password (password)
  "Prompt user a for the password for the current buffer.

PASSWORD ansible-vault password to be stored."
  (interactive
   (list (read-passwd "Vault Password: ")))
  (ansible-vault--create-password-file password))

(defun ansible-vault--request-vault-id (vault-id &optional password-file)
  "Prompt user for a vault-id for the current buffer.

If the vault-id doesn't have an associated password file, request
a password from the user as well.

VAULT-ID ansible-vault vault id.
PASSWORD-FILE path to the stored secret for provided VAULT-ID."
  (interactive "Vault Id: ")
  (let* ((vault-id-pair
          (or (assoc vault-id ansible-vault-vault-id-alist)
              (let* ((password-file (or password-file
                                        (call-interactively 'ansible-vault--request-password))))
                (car (push (cons vault-id password-file) ansible-vault-vault-id-alist)))))
         (password-file (or password-file (cdr vault-id-pair))))
    (setq-local ansible-vault--vault-id vault-id)
    (setq-local ansible-vault--password-file password-file)
    vault-id-pair))
