;; ──────────────────────────────────────────────────────────────
;; Ansible Documentation Snippets
;; ──────────────────────────────────────────────────────────────

;; ansible-vault variables
;; https://docs.ansible.com/ansible/latest/reference_appendices/config.html

;; DEFAULT_VAULT_PASSWORD_FILE ANSIBLE_VAULT_PASSWORD_FILE
;; [defaults] vault_password_file None
;; 
;; The vault password file to use. Equivalent to --vault-password-file or --vault-id. If executable,
;; it will be run and the resulting stdout will be used as the password.

;; DEFAULT_VAULT_IDENTITY_LIST ANSIBLE_VAULT_IDENTITY_LIST
;; [defaults] vault_identity_list []
;; 
;; A list of vault-ids to use by default. Equivalent to multiple --vault-id args. Vault-ids are
;; tried in order.

;; DEFAULT_VAULT_IDENTITY ANSIBLE_VAULT_IDENTITY
;; [defaults] vault_identity default
;; 
;; The label to use for the default vault id label in cases where a vault id label is not provided.

;; DEFAULT_VAULT_ENCRYPT_IDENTITY ANSIBLE_VAULT_ENCRYPT_IDENTITY
;; [defaults] vault_encrypt_identity
;; 
;; The vault_id to use for encrypting by default. If multiple vault_ids are provided, this specifies
;; which to use for encryption. The --encrypt-vault-id CLI option overrides the configured value.

;; DEFAULT_VAULT_ID_MATCH ANSIBLE_VAULT_ID_MATCH
;; [defaults] vault_id_match false
;; 
;; If true, decrypting vaults with a vault id will only try the password from the matching vault-id.

;; ──────────────────────────────────────────────────────────────
;; TODO list
;; ──────────────────────────────────────────────────────────────

;; version 1.0 will be released after implementing this

;; TODO: add menu
;; 1) possibility to check current crypto-options
;; 2) possibility to check current header-options
;; 3) possibility to check current ansible.cfg path
;; 4) ability to change crypto-options
;; 5) ability to change header-options

;; TODO: add ansible.cfg monitoring
;; 1) if ansible.cfg modified, refresh it and reinit crypto- and header-options
;; 2) if a more clouse ansible.cfg found, refresh options

;; TODO: add magit integration
;; 1) to watch diffs -- maybe there're other options
;; 2) to revert hunks -- mandatory

;; TODO: add inline ansible-vault snippets support (markers + overlays)

;; TODO: add rekey functionality

;; TODO: add a graphical header for encrypted region (or file)

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
