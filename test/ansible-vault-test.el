(require 'ert)
(load-file "../ansible-vault.el")


(ert-deftest ansible-vault--header-options ()
  (let ((v11  (a-list :version "1.1" :cipher-algorithm "AES256"))
        (v12  (a-list :version "1.2" :cipher-algorithm "AES256" :vault-id "dev"))
        (v13  (a-list :version "1.3" :cipher-algorithm "AES256"))
        (nv12 (a-list :version "1.2" :cipher-algorithm "AES256")))
    (should (equal (ansible-vault--header-options-p v11)   t))
    (should (equal (ansible-vault--header-options-p v12)   t))
    (should (equal (ansible-vault--header-options-p v13)   nil))
    (should (equal (ansible-vault--header-options-p nv12)  nil))))

(ert-deftest ansible-vault--crypto-options ()
  (let* ((v1  (a-list :vault-password-file ".vault-pass"
                      :vault-identity-list "dev@.vault-pass-dev, prod@.vault-pass-prod"))
         (v2  (a-assoc v1 :vault-encrypt-identity "dev")))
    (should (equal (ansible-vault--crypto-options-p v1) t))
    (should (equal (ansible-vault--crypto-options--can-decrypt-1.1-p v1) t))
    (should (equal (ansible-vault--crypto-options--can-encrypt-1.1-p v1) t))
    (should (equal (ansible-vault--crypto-options--can-decrypt-1.2-p v1) t))
    (should (equal (ansible-vault--crypto-options--can-encrypt-1.2-p v1) nil))
    (should (equal (ansible-vault--crypto-options--can-encrypt-1.2-p v2) t))))

(ert-deftest ansible-vault--crypto-options--validate ()
  (let* ((obj (a-list :vault-password-file ".vault-pass"
                      :vault-identity-list "dev@.vault-id-pass-dev, none@prompt, prod@.vault-id-pass-prod"
                      :vault-identity "dev"
                      :vault-encrypt-identity "dev"
                      :vault-id-match "true"))
         (obj (ansible-vault--crypto-options--validate obj)))
    (should (equal (a-get obj :vault-identity-list) "dev@.vault-id-pass-dev, prod@.vault-id-pass-prod"))))

(ert-deftest ansible-vault--vault-id-list ()
  (let ((str "dev@.vault-pass-dev, prod@.vault-pass-prod, none@prompt"))
    (should (equal (ansible-vault--vault-id-list--validate str) "dev@.vault-pass-dev, prod@.vault-pass-prod"))))

(ert-deftest test-ansible-vault--state-functions ()
  (with-temp-buffer
    (setq-local ansible-vault--state '())
    (ansible-vault--set-state :point 0)
    (ansible-vault--set-state :buffer :header-options :version "1.2")
    (ansible-vault--set-state :buffer :header-options :cipher-algorithm "AES256")
    (ansible-vault--set-state :buffer :header-options :vault-id "dev")
    (should (equal 0        (ansible-vault--get-state :point)))
    (should (equal "1.2"    (ansible-vault--get-state :buffer :header-options :version)))
    (should (equal "AES256" (ansible-vault--get-state :buffer :header-options :cipher-algorithm)))
    (should (equal "dev"    (ansible-vault--get-state :buffer :header-options :vault-id)))
    (should (equal nil      (ansible-vault--get-state :xxx)))
    ))

(ert-deftest test-ansible-vault--header-parsing ()
  (with-temp-buffer
    ;; init buffer
    (setq buffer-file-name "not-exist.yaml")
    (insert "$ANSIBLE_VAULT;1.2;AES256;dev\n")
    (insert "12345")
    (set-buffer-modified-p nil)
    ;; init pseudo-mode
    (setq-local ansible-vault--state '())
    ;; run
    (ansible-vault--buffer--encrypted--init-header-options)
    ;; test
    (should (equal "1.2"    (ansible-vault--get-state :buffer :header-options :version)))
    (should (equal "AES256" (ansible-vault--get-state :buffer :header-options :cipher-algorithm)))
    (should (equal "dev"    (ansible-vault--get-state :buffer :header-options :vault-id)))))

(ert-deftest ansible-vault--is-buffer-encrypted ()
  (with-temp-buffer
    (insert "$ANSIBLE_VAULT;1.2;AES256;dev\n")
    (should (equal t (ansible-vault--buffer--encrypted-p)))
    (erase-buffer)
    (should (equal nil (ansible-vault--buffer--encrypted-p)))
    (insert "$ANSIBLE_VAULT;1.1;AES256\n")
    (should (equal t (ansible-vault--buffer--encrypted-p)))
    ))

(ert-deftest ansible-vault--ansible-cfg-functions ()
  (with-temp-buffer
    ;; emulate file open procedure w/o enabling any modes
    (setq buffer-file-name (f-full "encrypted-1.1.yaml"))
    (insert-file-contents "encrypted-1.1.yaml")
    (set-buffer-modified-p nil)
    ;; enable pseudo ansible-vault-mode
    (setq-local ansible-vault--state '())
    ;; test
    (ansible-vault--ansible-cfg--init-crypto-options)
    (should (equal (ansible-vault--get-state :ansible-cfg :path) (f-full "ansible.cfg")))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-identity-list)
                   (concat "dev@" (f-full ".vault-id-pass-dev") ", "
                           "prod@" (f-full ".vault-id-pass-prod") ", "
                           "none@" (f-full ".vault-pass"))))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-password-file)      ".vault-pass"))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-identity)           "dev"))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-encrypt-identity)   "dev"))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-id-match)           "true"))
    ))

(ert-deftest ansible-vault--generate-shell-command ()
  (with-temp-buffer
    ;; enable pseudo ansible-vault-mode
    (setq-local ansible-vault--state '())
    ;; open file encrypted-1.1.yaml
    (setq buffer-file-name (f-full "encrypted-1.1.yaml"))
    (insert-file-contents "encrypted-1.1.yaml")
    (set-buffer-modified-p nil)
    ;; test
    (ansible-vault--buffer--encrypted--init-header-options)
    (ansible-vault--ansible-cfg--init-crypto-options)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer :header-options))
                   "ansible-vault decrypt --output=- --vault-password-file .vault-pass"))
    ;; open file encrypted-1.2-dev.yaml
    (setq buffer-file-name (f-full "encrypted-1.2-dev.yaml"))
    (insert-file-contents "encrypted-1.2-dev.yaml")
    (set-buffer-modified-p nil)
    ;; test
    (ansible-vault--buffer--encrypted--init-header-options)
    (ansible-vault--ansible-cfg--init-crypto-options)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer :header-options))
                   (concat "ansible-vault decrypt --output=-"
                           " --vault-id dev@" (f-full ".vault-id-pass-dev")
                           " --vault-id prod@" (f-full ".vault-id-pass-prod")
                           " --vault-id none@" (f-full ".vault-pass"))))))

(ert-deftest ansible-vault--run ()
  (with-temp-buffer
    ;; enable pseudo ansible-vault-mode
    (setq-local ansible-vault--state '())
    ;; open file encrypted-1.1.yaml
    (setq buffer-file-name (f-full "encrypted-1.1.yaml"))
    (insert-file-contents "encrypted-1.1.yaml")
    (set-buffer-modified-p nil)
    ;; test
    (ansible-vault--buffer--encrypted--init-header-options)
    (ansible-vault--ansible-cfg--init-crypto-options)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer :header-options))
                   "ansible-vault decrypt --output=- --vault-password-file .vault-pass"))
    (let ((decrypted-string
           (ansible-vault--run :decrypt
                               (ansible-vault--get-state :ansible-cfg :crypto-options)
                               (ansible-vault--get-state :buffer :header-options)
                               (buffer-string))))
      (should (equal decrypted-string "---
creds:
  user: \"my-service-user\"
  pass: \"my-secret-password\"

...
")))))

                     
(provide 'ansible-vault-test)
