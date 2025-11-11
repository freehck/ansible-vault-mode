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
