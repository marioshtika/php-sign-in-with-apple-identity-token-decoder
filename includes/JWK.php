<?php

class JWK
{
    public static function parseKeySet($source)
    {
        $keys = [];
        if (is_string($source)) {
            $source = json_decode($source, true);
        } else if (is_object($source)) {
            if (property_exists($source, 'keys'))
                $source = (array) $source;
            else
                $source = [$source];
        }

        if (is_array($source)) {
            if (isset($source['keys']))
                $source = $source['keys'];

            foreach ($source as $k => $v) {
                if (!is_string($k)) {
                    if (is_array($v) && isset($v['kid']))
                        $k = $v['kid'];
                    elseif (is_object($v) && property_exists($v, 'kid'))
                        $k = $v->{'kid'};
                }
                try {
                    $v = self::parseKey($v);
                    $keys[$k] = $v;
                } catch (Exception $e) {
                    //Do nothing
                }
            }
        }
        if (0 < count($keys)) {
            return $keys;
        }

        throw new Exception('Failed to parse JWK');
    }

    public static function parseKey($source)
    {
        if (!is_array($source))
            $source = (array) $source;
        if (!empty($source) && isset($source['kty']) && isset($source['n']) && isset($source['e'])) {
            switch ($source['kty']) {
                case 'RSA':
                    if (array_key_exists('d', $source))
                        throw new Exception('Failed to parse JWK: RSA private key is not supported');

                    $pem = self::createPemFromModulusAndExponent($source['n'], $source['e']);
                    $pKey = openssl_pkey_get_public($pem);
                    if ($pKey !== false)
                        return $pKey;
                    break;
                default:
                    //Currently only RSA is supported
                    break;
            }
        }

        throw new Exception('Failed to parse JWK');
    }

    private static function createPemFromModulusAndExponent($n, $e)
    {
        $modulus = JWT::urlsafeB64Decode($n);
        $publicExponent = JWT::urlsafeB64Decode($e);


        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );

        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );


        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }

    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
