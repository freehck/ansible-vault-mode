(require 'ert)
(load-file "../ansible-vault.el")

(ert-deftest test-ansible-vault--state-functions ()
  (with-temp-buffer
    (setq-local ansible-vault--state '())
    (ansible-vault--set-state :point 0)
    (ansible-vault--set-state :buffer-header :version "1.2")
    (ansible-vault--set-state :buffer-header :cipher-algorithm "AES256")
    (ansible-vault--set-state :buffer-header :vault-id "dev")
    (should (equal 0        (ansible-vault--get-state :point)))
    (should (equal "1.2"    (ansible-vault--get-state :buffer-header :version)))
    (should (equal "AES256" (ansible-vault--get-state :buffer-header :cipher-algorithm)))
    (should (equal "dev"    (ansible-vault--get-state :buffer-header :vault-id)))
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
    (ansible-vault--encrypted-buffer--init-state-header)
    ;; test
    (should (equal "1.2"    (ansible-vault--get-state :buffer-header :version)))
    (should (equal "AES256" (ansible-vault--get-state :buffer-header :cipher-algorithm)))
    (should (equal "dev"    (ansible-vault--get-state :buffer-header :vault-id)))))

(ert-deftest ansible-vault--is-buffer-encrypted ()
  (with-temp-buffer
    (insert "$ANSIBLE_VAULT;1.2;AES256;dev\n")
    (should (equal t (ansible-vault--is-buffer-encrypted)))
    (erase-buffer)
    (should (equal nil (ansible-vault--is-buffer-encrypted)))
    (insert "$ANSIBLE_VAULT;1.1;AES256\n")
    (should (equal t (ansible-vault--is-buffer-encrypted)))
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
    (ansible-vault--init-state-ansible-cfg)
    (should (equal (ansible-vault--get-state :ansible-cfg :path) (f-full "ansible.cfg")))
    (should (equal (ansible-vault--get-state :ansible-cfg :crypto-options :vault-identity-list)
                   "dev@.vault-id-pass-dev, prod@.vault-id-pass-prod, none@.vault-pass"))
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
    (ansible-vault--encrypted-buffer--init-state-header)
    (ansible-vault--init-state-ansible-cfg)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer-header))
                   "ansible-vault decrypt --output=- --vault-password-file .vault-pass"))
    ;; open file encrypted-1.2-dev.yaml
    (setq buffer-file-name (f-full "encrypted-1.2-dev.yaml"))
    (insert-file-contents "encrypted-1.2-dev.yaml")
    (set-buffer-modified-p nil)
    ;; test
    (ansible-vault--encrypted-buffer--init-state-header)
    (ansible-vault--init-state-ansible-cfg)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer-header))
                   "ansible-vault decrypt --output=- --vault-id dev@.vault-id-pass-dev --vault-id prod@.vault-id-pass-prod --vault-id none@.vault-pass"))))

(ert-deftest ansible-vault--run ()
  (with-temp-buffer
    ;; enable pseudo ansible-vault-mode
    (setq-local ansible-vault--state '())
    ;; open file encrypted-1.1.yaml
    (setq buffer-file-name (f-full "encrypted-1.1.yaml"))
    (insert-file-contents "encrypted-1.1.yaml")
    (set-buffer-modified-p nil)
    ;; test
    (ansible-vault--encrypted-buffer--init-state-header)
    (ansible-vault--init-state-ansible-cfg)
    (should (equal (ansible-vault--generate-shell-command
                    :decrypt
                    (ansible-vault--get-state :ansible-cfg :crypto-options)
                    (ansible-vault--get-state :buffer-header))
                   "ansible-vault decrypt --output=- --vault-password-file .vault-pass"))
    (let ((decrypted-string
           (ansible-vault--run :decrypt
                               (ansible-vault--get-state :ansible-cfg :crypto-options)
                               (ansible-vault--get-state :buffer-header)
                               (buffer-string))))
      (should (equal decrypted-string "---
creds:
  user: \"my-service-user\"
  pass: \"my-secret-password\"

...
")))))

                     
(provide 'ansible-vault-test)
