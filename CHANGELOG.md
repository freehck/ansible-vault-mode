## Changelog

### version 0.7.0

Full rewrite.

- Stop using `magic-mode-alist` as it was intended for major modes only, migrated to
  `auto-minor-mode-magic-alist` from `auto-minor-mode` package.
- Stop using temporary files. Nothing to clean now when we disable mode.
- Move all the state variables into a separate alist.
- Add ERT tests.
- Fix toggling mode problem (#27, #29, #34).


### version 0.6.1

 - Add compatibility fixes for Emacs 26.1 (issue #24)
 - Add magic-mode-alist integration (issue #26)

### version 0.6.0

 - Now `ansible-vault-mode` allows to change major mode, and even do it by default right after
   initialization, so you can work with encrypted files as if they were the ordinary ones. They will
   be re-encrypted when you save your changes.
   
 

### version 0.5.0 and beyond

 - `ansible-vault-mode` is now more aggressive in detecting valid password files. If it fails to
   locate a valid password file it will prompt the user for input.

 - The minor mode now defines some key bindings under `C-c a`
    - `C-c a d` Decrypts the current file and saves it
    - `C-c a D` Decrypts the current region
    - `C-c a e` Encrypts the current file and saves it
    - `C-c a E` Encrypts the current region
    - `C-c a p` Updates the password of the current buffer
    - `C-c a i` Updates the vault-id of the current buffer


