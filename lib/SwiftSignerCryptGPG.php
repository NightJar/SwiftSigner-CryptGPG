<?php

namespace Nightjar;

use Crypt_GPG;
use Swift_Attachment;
use Swift_Encoding;
use Swift_Message;
use Swift_Signers_BodySigner;

class SwiftSignerCryptGPG implements Swift_Signers_BodySigner
{
    /**
     * Instance of Crypt_GPG
     *
     * @var Crypt_GPG
     */
    private $gpg;

    /**
     * Whether or not to sign the email also. Controlled via the presence of a signing key in the constructor (or not).
     *
     * @var boolean
     */
    private $sign = false;

    /**
     * Constructor.
     *
     * @param string $encryptKey
     * @param string $signKey
     * @param string $passphrase
     * @param array $options
     */
    public function __construct(string $encryptKey, string $signKey = '', string $passphrase = '', array $options = [])
    {
        $gpg = new Crypt_GPG($options);
        $gpg->addEncryptKey($encryptKey);
        if ($signKey) {
            $gpg->addSignKey($signKey, $passphrase ?: null);
            $this->sign = true;
        }
        $this->gpg = $gpg;
    }

    public function reset()
    {
        return $this;
    }

    public function signMessage(Swift_Message $message)
    {
        // Copy message - cloning would also copy the signers.
        // This is to avoid an infinite loop when getting the message as a string - toString calls doSign first!
        $messageCopy = Swift_Message::newInstance(
            $message->getSubject(),
            $message->getBody(),
            $message->getContentType(),
            $message->getCharset()
        );

        // Remove now irrelevant headers from copy to be encrypted
        $headers = $messageCopy->getHeaders();
        foreach (['message-id', 'date', 'subject', 'from', 'to', 'cc', 'bcc'] as $headerName) {
            $headers->removeAll($headerName);
        }
        $messageCopy->setChildren($message->getChildren());

        // Encrypt
        $body = $messageCopy->toString();
        $encryptedBody = $this->sign
            ? $this->gpg->encryptAndSign($body)
            : $this->gpg->encrypt($body);

        // Format PGP/MIME
        $encoder = Swift_Encoding::get7BitEncoding();

        $pgpmime = Swift_Attachment::newInstance('Version: 1')
            ->setContentType('application/pgp-encrypted')
            ->setEncoder($encoder);
        $pgpmime->getHeaders()->remove('Content-Transfer-Encoding');

        $encryptedMessage = Swift_Attachment::newInstance($encryptedBody, 'message.asc')
            ->setEncoder($encoder);
        $encryptedMessage->getHeaders()->remove('Content-Transfer-Encoding');

        // Prepare message final form
        $message
            ->setEncoder($encoder)
            ->setChildren([$pgpmime, $encryptedMessage]);

        $type = $message->getHeaders()->get('Content-Type');
        $type->setValue('multipart/encrypted');
        $type->setParameter('protocol', 'application/pgp-encrypted');

        return $this;
    }

    public function getAlteredHeaders()
    {
        return [];
    }

    /**
     * Returns a new SwiftSignerCryptGPG instance
     *
     * @param string $encryptKey
     * @param string $signKey
     * @param string $passphrase
     * @param array $options
     * @return self
     */
    public static function newInstance(
        string $encryptKey,
        string $signKey = '',
        string $passphrase = '',
        array $options = []
    ) {
        return new self($encryptKey, $signKey, $passphrase, $options);
    }
}
