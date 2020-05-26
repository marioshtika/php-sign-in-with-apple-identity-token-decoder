Sign in with Apple - Identity token decoder
===========================================

Based on [GriffinLedingham/php-apple-signin](https://github.com/GriffinLedingham/php-apple-signin) repository

This should be used to decode the identity token returned by Apple.
I would not recommend passing the token through, by the iOS client.

Example
-------
```php
<?php

require_once('includes/apple-signin-decoder.php');
require_once('includes/JWT.php');
require_once('includes/JWK.php');

try {
    $identityToken = "example_identity_token";
    $appleSignInPayload = new AppleSignInDecoder($identityToken);

    $email = $appleSignInPayload->getEmail();
    $user = $appleSignInPayload->getUser();
} catch (Exception $error) {
    echo $error->getMessage();
}

?>
```
