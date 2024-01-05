<?php
class EntrarService extends Services
{
    private $secret, $app_id, $api_key, $token, $subdomain, $url_login_success;

    public function __construct($db_conf = [])
    {
        global $_APP_VAULT;
        $this->subdomain = $_APP_VAULT['ENTRAR']['SUBDOMAIN'];
        $this->url_login_success = $_APP_VAULT['ENTRAR']['URL']['LOGIN_SUCCESS'];
        $this->secret = getenv('JWT_SECRET');
        $this->app_id = getenv('APP_ID');
        $this->api_key = getenv('API_KEY');
        $this->token = base64_encode("$this->app_id:$this->api_key");
    }
    public function get($endpoint, $body_data = [])
    {
        return $this->curl($endpoint, 'GET', $body_data);
    }
    public function post($endpoint, $body_data = [])
    {
        return $this->curl($endpoint, 'POST', $body_data);
    }
    public function put($endpoint, $body_data = [])
    {
        return $this->curl($endpoint, 'PUT', $body_data);
    }
    private function curl($endpoint, $type = 'GET', $body_data = [])
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://{$this->subdomain}.entrar.app/api/$endpoint");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer $this->token"
        ]);
        // Body data
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $type);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body_data));
        $res = curl_exec($ch);
        // Check error
        if (curl_errno($ch)) return $this->error(curl_error($ch));
        // Return
        curl_close($ch);
        $data = @json_decode($res, true)['data'];
        return $this->res($data);
    }
    public function validateAccess($jwt)
    {
        list($header, $payload, $signature) = explode('.', $jwt);
        $validSignature = hash_hmac('sha256', $header . "." . $payload, $this->secret, true);
        $validSignatureEncoded = $this->base64UrlEncode($validSignature);
        if ($signature !== $validSignatureEncoded) return $this->error("Invalid JWT signature");
        $payloadDecoded = json_decode($this->base64UrlDecode($payload), true);
        if ($payloadDecoded['exp'] < time()) return $this->error("Expired JWT");
        return $this->res($payloadDecoded);
    }
    private function base64UrlEncode($data)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
    private function base64UrlDecode($data)
    {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
    }
    public function verifyAccess()
    {
        if (@$_SESSION['auth']['access_token']) {
            //echo "<h1>checking existing access token...</h1>";
            $login_url = "https://{$this->subdomain}.entrar.app/auth/login";
            $access_token = @$_SESSION['auth']['access_token'];
            $refresh_token = @$_SESSION['auth']['refresh_token'];
            $user_id = @$_SESSION['auth']['user_id'];
            // Validate
            if (!$this->validateAccess($access_token)) {
                unset($_SESSION['auth']); // logout
                //echo "<p>{$this->error}. Getting new token...</p>";
                //echo "<p>refresh=$refresh_token</p>";
                if ($refresh_token) {
                    $new_tokens = $this->get("refresh-token", ["user_id" => $user_id, "refresh_token" => $refresh_token]);
                    // Fail to get new token
                    if (!@$new_tokens['access_token']) {
                        header("Location: $login_url");
                        exit;
                    }
                    // Success
                    else {
                        //echo "<p>Success!</p>";
                        //pre($new_tokens);
                        $this->createUserSession($user_id, $new_tokens['access_token'], $new_tokens['refresh_token']);
                    }
                }
            } //else echo 'valid!';
        }
    }
    public function createUserSession($user_id, $access_token, $refresh_token)
    {
        // Logout
        unset($_SESSION['auth']);
        // Get user data
        $user = new EntrarService();
        $user_data = $user->get("user/$user_id");
        // Create new login session
        if ($user_data['user_status'] == 1) {
            sessionImportArray(['auth' => $user_data]);
            $_SESSION['auth']['access_token'] = $access_token;
            $_SESSION['auth']['refresh_token'] = $refresh_token;
        }
    }
    public function verifyLoginPost()
    {
        // Coming from entrar.app ?
        $referrer = @$_SERVER['HTTP_REFERER'];
        $domain = parse_url($referrer, PHP_URL_HOST);
        if ($domain !== "{$this->subdomain}.entrar.app") die('Invalid referrer');

        // Check Post
        if (@!$_POST['access_token']) die('Data not found');

        // Check Token
        $access_token = $_POST['access_token'];
        $refresh_token = @$_POST['refresh_token'];
        $validate = new EntrarService();
        $validate->validateAccess($access_token);

        // Error
        if ($validate->error) die($validate->error);

        // Success
        $jwt_data = json_decode($validate->res['user'], true);
        $user_id = $jwt_data['user_id'];
        $this->createUserSession($user_id, $access_token, $refresh_token);
        //die($this->url_login_success);
        // Redirect
        header("Location: {$this->url_login_success}");
        exit;
    }
}
