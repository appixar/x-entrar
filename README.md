# Hello world

```php:
# pages/inc-auth.php
# ... incluir no topo de PAGES em config.yml
$entrar = new EntrarService();
$entrar->verifyAccess();

if (@!$_SESSION['auth']) {
    header("Location: https://sellerai.entrar.app/auth");
    exit;
}
```