(require 'ert)
(load-file "../ansible-vault-snippets.el")


(ert-deftest macroexpand:with-local-aliases ()
  (should (equal
           (macroexpand-all
            '(ansible-vault--with-local-aliases
               (let ((ehdr (make-ehdr :parse-string "$ANSIBLE_VAULT;1.2;AES256;dev")))
                 ehdr)))
           '(progn
              (let ((ehdr (ansible-vault--make-ehdr :parse-string "$ANSIBLE_VAULT;1.2;AES256;dev")))
                ehdr))))
  (should (equal
           (macroexpand-all
            '(ansible-vault--with-local-aliases
               (string-match ehdr-regex str)))
           '(progn
              (string-match ansible-vault--ehdr-regex str))))
  (should (equal
           (macroexpand-all
            '(ansible-vault--with-local-aliases
               (apply #'make-ehdr-orig plist)))
           '(progn
              (apply #'make-ansible-vault--ehdr plist)))))

(ert-deftest structure:ehdr ()
  (ansible-vault--with-local-aliases
    (let ((ehdr (make-ehdr :parse-string "$ANSIBLE_VAULT;1.1;AES256")))
      (should (equal (ehdr-cipher-algorithm ehdr) "AES256"))
      (should (equal (ehdr-vault-type ehdr) 'password-file))
      (should (equal (ehdr-vault-id ehdr) nil))
      )
    (let ((ehdr (make-ehdr :parse-string "$ANSIBLE_VAULT;1.2;AES256;dev")))
      (should (equal (ehdr-cipher-algorithm ehdr) "AES256"))
      (should (equal (ehdr-vault-type ehdr) 'vault-id))
      (should (equal (ehdr-vault-id ehdr) "dev"))
      )))

(ert-deftest structure:vault-id-alist ()
  (ansible-vault--with-local-aliases
    (let ((vault-id-alist (make-vault-id-alist :parse-string "dev@.vault-id-pass-dev, prod@.vault-id-pass-prod"
                                               :basedir "general")))
      (should (equal (a-get vault-id-alist "dev") (f-full "general/.vault-id-pass-dev")))
      (should (equal (a-get vault-id-alist "prod") (f-full "general/.vault-id-pass-prod")))
      (should (equal (a-get vault-id-alist "none") nil)))))

(ert-deftest structure:avo ()  
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "general/encrypted-1.1.yaml"))
      (insert-file-contents "general/encrypted-1.1.yaml")
      (set-buffer-modified-p nil)
      ;; test
      (should (equal (avo-locate-ansible-cfg) (f-full "general/ansible.cfg")))
      (let ((avo (make-avo :by-current-buffer)))
        (should (equal (avo-ansible-cfg-path avo) (f-full "general/ansible.cfg")))
        (should (equal (avo-password-file avo) (f-full "general/.vault-pass")))
        (should (equal (avo-default-enc-vault-id avo) "dev"))
        (should (equal (avo-default-vault-id avo) "dev"))
        (should (equal (a-get (avo-vault-id-alist avo) "dev") (f-full "general/.vault-id-pass-dev")))
        (should (equal (a-get (avo-vault-id-alist avo) "prod") (f-full "general/.vault-id-pass-prod")))))))
    
