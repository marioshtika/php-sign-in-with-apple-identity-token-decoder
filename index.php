<?php

require_once('includes/apple-signin-decoder.php');
require_once('includes/JWT.php');
require_once('includes/JWK.php');

try {
    $appleSignInPayload = new AppleSignInDecoder($identityToken);

    $email = $appleSignInPayload->getEmail();
    $user = $appleSignInPayload->getUser();
} catch (Exception $error) {
    echo $error->getMessage();
}
