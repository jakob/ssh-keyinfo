# ssh-keyinfo
A tool that parses OpenSSH privat key files

Have you ever wondered what's inside an SSH key?

If you just print the contents of the file, you won't see much:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAzLDHPvth4M+vJrHdpx5RwdiAe8flkgctgTTuSDsYS7QAAAJhyjZwoco2c
KAAAAAtzc2gtZWQyNTUxOQAAACAzLDHPvth4M+vJrHdpx5RwdiAe8flkgctgTTuSDsYS7Q
AAAED5rGvXcXluVF7Kp7j0UQbLajkYrJNlLuVmkWuNf8FK3TMsMc++2Hgz68msd2nHlHB2
IB7x+WSBy2BNO5IOxhLtAAAAFHRlc3R1c2VyQHRlc3RtYWNoaW5lAQ==
-----END OPENSSH PRIVATE KEY-----
```

That's why I wrote ssh-keyinfo. Assuming the key above is in a file titled id_ed25519, you can print its contents like this:

```zsh
% python3 ssh-keyinfo.py id_ed25519

id_ed25519:
  length = 250 bytes
  Key File Format: OpenSSH Key File Format Version 1
  ciphername: none
  kdfname: none
  kdfoptions: b''
  number of keys: 1
  public key 1:
    type: ssh-ed25519
    data: Mywxz77YeDPryax3aceUcHYgHvH5ZIHLYE07kg7GEu0=
  checkints: 1921883176==1921883176
  private key 1:
    type: ssh-ed25519
    Parameters:
      Public Key = Mywxz77YeDPryax3aceUcHYgHvH5ZIHLYE07kg7GEu0=
      Private Key = +axr13F5blReyqe49FEGy2o5GKyTZS7lZpFrjX/BSt0zLDHPvth4M+vJrHdpx5RwdiAe8flkgctgTTuSDsYS7Q==
    comment: testuser@testmachine

```

ssh-keyinfo is written in Python and currently has no other dependencies.

Current Limitations:
-------------------

- supports only OpenSSH private key file format
- does not support decrypting private keys yet