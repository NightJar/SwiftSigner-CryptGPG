# PHP based emails protected via OpenPGP

This library extends the somewhat ubiqitious [SwiftMailer](https://github.com/swiftmailer/swiftmailer) package by providing a class to fit the Message Signer API to implement PGP encryption and optionally signing.

## Usage

One must have a keyring set up and accessible, as per the requirements of the [Crypt_GPG](https://github.com/pear/Crypt_GPG) library.
This means that PHP must also have permission to shell out commands via [`proc_open`](https://www.php.net/proc_open)

```
$encryptionKeyID = 'recipient@example.test';
$signer = new \Nightjar\SwiftSignerCryptGPG($encryptionKeyID);
/** @var Swift_Message $swiftMessage */
$swiftMessage->attachSigner($signer);
```

Upon sending the message it will be encrypted as per PGP/MIME ([RFC 3156](https://tools.ietf.org/html/rfc3156))

## Limitations and future development
Currently encryption is mandatory, signing is optional. This should change to provide a signing only option in the future.
