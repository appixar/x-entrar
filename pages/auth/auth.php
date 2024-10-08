<?php
if (!@$_SESSION['auth']) {
    $subdom = @$_APP_VAULT['ENTRAR']['SUBDOMAIN'];
    if ($subdom) header("Location: https://$subdom.entrar.app/auth");
    exit;
}
else {
    $goto = @$_APP_VAULT['ENTRAR']['URL']['LOGIN_SUCCESS'];
    if ($goto) header("Location: $goto");
    exit;
}