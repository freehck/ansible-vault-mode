[![MELPA Stable](https://stable.melpa.org/packages/ansible-vault-badge.svg)](melpa-stable)
[![MELPA](https://melpa.org/packages/ansible-vault-badge.svg)](melpa)

# ansible-vault-mode

Minor mode for editing files encrypted by [ansible-vault][ansible-vault].

The package is available in [MELPA Stable](melpa-stable) and [MELPA](melpa).

## Installation

### Recommended way

Put this into `~/.emacs`:

```lisp
(use-package ansible-vault :ensure t)
```

### Manual way

```
M-x package-install RET ansible-vault RET
```

## Usage

By default the mode is enabled automatically when you open an encrypted file by using
`auto-minor-mode-magic-alist` (from [auto-minor-mode](auto-minor-mode)). You can disable this
behaviour by setting `ansible-vault-mode-enable-by-magic` to `nil`.

When enabled, the mode tries to find `ansible.cfg` file. First it checks `ANSIBLE_CONFIG`
environment variable. If not set, it performs an upward search starting from your encrypted file
location. Then it tries `~/.ansible.cfg` and eventually `/etc/ansible/ansible.cfg`. When
`ansible.cfg` found, it is parsed in order to get `ansible-vault` configuration parameters. These
parameters will be associated with the file buffer and will be used to run `ansible-vault` binary
to perform decryption and encryption.

The recommendation is to store `ansible.cfg` in the root of the repo with your ansible code.

By default when you open an encrypted file it will be decrypted automatically. You can disable this
behaviour by setting `ansible-vault-auto-decrypt` to `nil`.

The mode uses hooks `before-save-hook` and `after-save-hook`. So when you save your file it will be
re-encrypted back.

By default the mode will try to determine and enable an appropriate major mode by calling
`normal-mode` after initialization. This means that major modes that must be activated by
`magic-mode-alist` will be activated as if your file wasn't encrypted. You can disable this
behaviour by setting `ansible-vault-auto-determine-major-mode-by-decrypted-content` to `nil`.

In case of errors have a look into ```*ansible-vault-error*``` buffer.

All the variables described above can by constomized with
`M-x customize-group RET ansible-vault RET`


## Release Notes

Look into [CHANGELOG.md](changelog).




## Contributing

Bug reports and pull requests are welcome on [GitHub issues][issues].

Feature requests are welcome too, but I strongly recommend to consider filing a PR additionally.



## License

This program is licensed under [GPLv3][license].



## Authors and Contributors

Zachary Elliott &lt;contact@zell.io&gt;<br/>
Dmitrii Kashin  &lt;freehck@yandex.ru&gt;<br/>
Peter Bray      [@illumino](https://github.com/illumino)<br/>



[ansible-vault]: http://docs.ansible.com/ansible/playbooks_vault.html
[yaml]: http://yaml.org/
[issues]: https://github.com/freehck/ansible-vault-mode
[license]: LICENSE
[changelog]: CHANGELOG.md
[melpa-stable]: https://stable.melpa.org/#/ansible-vault
[melpa]: https://melpa.org/#/ansible-vault
[auto-minor-mode]: https://stable.melpa.org/#/auto-minor-mode
