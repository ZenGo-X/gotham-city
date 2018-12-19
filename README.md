Gotham City
=====================================
![Gotham icon](https://raw.githubusercontent.com/KZen-networks/gotham-city/master/misc/illustration.png?token=AHSsRUMp2DSWlyhlHCEDYKCMNkErsKuXks5cI2ijwA%3D%3D)

Gotham city is a fully functional project to demonstrate real-life 
example of minimalist Bitcoin decentralized HD wallet using 2 party ECDSA.

Disclaimer
-------
Gotham city is a proof of concept. **The project should not be used in _production_!**

Project Status
-------
The project is currently work in progress (WIP).

Project Description
-------

### Design Overview

#### ECDSA Keygen and Signing
![ECDSA](misc/ecdsa-illustration.png)
* For details on Threshold Signatures see [Threshold Signatures: The Future of Private Keys](https://medium.com/kzen-networks/threshold-signatures-private-key-the-next-generation-f27b30793b)

#### Cryptographic libraries
* [zk-paillier](https://github.com/KZen-networks/zk-paillier)
* [kms](https://github.com/KZen-networks/kms)
* [multi-party-ecdsa](https://github.com/KZen-networks/multi-party-ecdsa)
* [curv](https://github.com/KZen-networks/curv)

### White paper overview
#### Abstract
We demonstrate a Bitcoin wallet that utilizes two party ECDSA (2P-ECDSA).
Our architecture consists of a simple client-server communication
model. We show support for 2 party deterministic child derivation
(2P-HD), secret share rotation and verifiable recovery. We discuss the
opportunities and challenges of using a multi-party wallet.

#### Background
For end-users, cryptocurrencies and blockchain-based assets are hard to store and manage.
One of the reasons is the tradeoff between security and availability.
Storing private keys safely requires dedicated hardware or extreme security measures which make using the coins
on a daily basis difficult. Threshold cryptography provides ways to decentralize the private key and digital signing.
This can potentially benefit security but at the same time reveal new challenges such as availability, ownership and recovery.
Bitcoin is utilizing ECDSA as the signing scheme. There is an active line of research for practical and efficient multi-party ECDSA schemes.

**For more information, see our [white paper](white-paper/white-paper.pdf)**.

Performance
-------
TODO

License
-------
Gotham City is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Contact
-------
For any questions, feel free to [email us](mailto:github@kzencorp.com).