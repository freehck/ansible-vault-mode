(require 'ert)
(load-file "../ansible-vault-snippets.el")

(ert-deftest macroexpand:with-local-aliases ()
  (should (equal
           (macroexpand-all
            '(ansible-vault--with-local-aliases
               (1 . 2)))
           '(progn (1 . 2))))
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

(ert-deftest macroexpand:with-temp-env ()
  (ansible-vault--with-local-aliases
    (let ((val "from-expr"))
      (with-temp-env ("TEST")
        (should (equal (getenv "TEST") nil))
        (with-temp-env (("TEST" . ((lambda () "from-inline-expr"))))
          (should (equal (getenv "TEST") "from-inline-expr"))
          (with-temp-env (("TEST" . val))
            (should (equal (getenv "TEST") "from-expr")))
          (should (equal (getenv "TEST") "from-inline-expr")))
        (should (equal (getenv "TEST") nil))))))

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
    
;;(ert-deftest structure:eblk ()
;;  (ansible-vault--with-local-aliases
;;    (with-temp-buffer
;;      ;; emulate file open procedure w/o enabling any modes
;;      (setq buffer-file-name (f-full "snippets/snippets.yaml"))
;;      (insert-file-contents "snippets/snippets.yaml")
;;      (set-buffer-modified-p nil)
;;      ;; test
;;      (let ((eblks (ansible-vault--eblk-find-all-in-buffer)))
;;        (should (equal (length eblks) 3))
;;        (let ((eblk-1 (nth 0 eblks))
;;              (eblk-2 (nth 1 eblks))
;;              (eblk-3 (nth 2 eblks)))
;;          (should (equal (overlay-start (eblk-overlay eblk-1))   49))
;;          (should (equal (overlay-end   (eblk-overlay eblk-1))   424))
;;          (should (equal (overlay-start (eblk-overlay eblk-2))   444))
;;          (should (equal (overlay-end   (eblk-overlay eblk-2))   823))
;;          (should (equal (overlay-start (eblk-overlay eblk-3))   844))
;;          (should (equal (overlay-end   (eblk-overlay eblk-3))   1224))
;;          ))))
;;  )

(ert-deftest cli:gen-shell-command:password-file ()
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "general/encrypted-1.1.yaml"))
      (insert-file-contents "general/encrypted-1.1.yaml")
      (set-buffer-modified-p nil)
      ;; test
      (let ((avo (make-avo :by-current-buffer))
            (ehdr (make-ehdr :parse-string (first-line (buffer-string)))))
        (should (equal (gen-shell-command 'decrypt avo ehdr)
                       (concat "ansible-vault decrypt --output=- --vault-password-file"
                               " " (f-full "general/.vault-pass"))))
        (should (equal (gen-shell-command 'encrypt avo ehdr)
                       (concat "ansible-vault encrypt --output=- --vault-password-file"
                               " " (f-full "general/.vault-pass"))))))))

(ert-deftest cli:gen-shell-command:vault-id:dev ()
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "general/encrypted-1.2-dev.yaml"))
      (insert-file-contents "general/encrypted-1.2-dev.yaml")
      (set-buffer-modified-p nil)
      ;; test
      (let ((avo (make-avo :by-current-buffer))
            (ehdr (make-ehdr :parse-string (first-line (buffer-string)))))
        (should (equal (gen-shell-command 'decrypt avo ehdr)
                       (concat "ansible-vault decrypt --output=-"
                               " --vault-id dev@" (f-full "general/.vault-id-pass-dev")
                               " --vault-id prod@" (f-full "general/.vault-id-pass-prod"))))
        (should (equal (gen-shell-command 'encrypt avo ehdr)
                       (concat "ansible-vault encrypt --output=-"
                               " --encrypt-vault-id dev"
                               " --vault-id dev@" (f-full "general/.vault-id-pass-dev"))))))))

(ert-deftest cli:run:password-file ()
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "snippets/encrypted-1.1"))
      (insert-file-contents "snippets/encrypted-1.1")
      (set-buffer-modified-p nil)
      ;; test
      (let ((avo (make-avo :by-current-buffer))
            (ehdr (make-ehdr :parse-string (first-line (buffer-string)))))
        (cl-flet ((decrypt (apply-partially #'av-decrypt avo ehdr))
                  (encrypt (apply-partially #'av-encrypt avo ehdr)))
          (should (equal (decrypt (buffer-string))                     '(ok . "user@password\n")))
          (should (equal (decrypt (encrypt (decrypt (buffer-string)))) '(ok . "user@password\n"))))))))

(ert-deftest cli:run:vault-id:dev ()
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "snippets/encrypted-1.2-dev"))
      (insert-file-contents "snippets/encrypted-1.2-dev")
      (set-buffer-modified-p nil)
      ;; test
      (let ((avo (make-avo :by-current-buffer))
            (ehdr (make-ehdr :parse-string (first-line (buffer-string)))))
        (cl-flet ((decrypt (apply-partially #'ansible-vault--run 'decrypt avo ehdr))
                  (encrypt (apply-partially #'ansible-vault--run 'encrypt avo ehdr)))
          (should (equal (decrypt (buffer-string))                     '(ok . "user@password\n")))
          (should (equal (decrypt (encrypt (decrypt (buffer-string)))) '(ok . "user@password\n"))))))))

(ert-deftest mode:run:password-file ()
  (ansible-vault--with-local-aliases
    (with-temp-buffer
      ;; emulate file open procedure w/o enabling any modes
      (setq buffer-file-name (f-full "snippets/encrypted-1.1"))
      (insert-file-contents "snippets/encrypted-1.1")
      (set-buffer-modified-p nil)
      ;; test
      (ansible-vault-mode-enable)
      (should (equal (buffer-string) "user@password\n"))))
  )


;;(ert-deftest structure:eblk:decrypt ()
;;  (ansible-vault--with-local-aliases
;;    (with-temp-buffer
;;      ;; emulate file open procedure w/o enabling any modes
;;      (setq buffer-file-name (f-full "snippets/snippets.yaml"))
;;      (insert-file-contents "snippets/snippets.yaml")
;;      (set-buffer-modified-p nil)
;;      ;; test
;;      (let ((eblks (ansible-vault--eblk-find-all-in-buffer))
;;            (avo (make-avo :by-current-buffer)))
;;        (should (equal (length eblks) 3))
;;        (let ((eblk-1 (nth 0 eblks))
;;              (eblk-2 (nth 1 eblks))
;;              (eblk-3 (nth 2 eblks)))
;;          (av-decrypt eblk)
;;
