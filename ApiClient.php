<?php
/**
 * Regtown B2B API client for the WISECP registrar module.
 */
    namespace WISECP\Modules\Registrars\Regtown;

    use Exception;

    class ApiClient
    {
        public const API_URL_SANDBOX = 'https://b2b-test-api.regtown.com';
        public const API_URL_PROD    = 'https://b2b-api.regtown.com';

        private const SECRET_KEYS = ['password', 'client_secret', 'auth_code', 'access_token', 'refresh_token'];

        public string $error = '';
        public int $timeout = 60;
        public int $connect_timeout = 15;

        /** function (string $action, mixed $request, mixed $response): void — set by the module to write WISECP module logs. */
        public ?\Closure $logger = null;

        private string $apiUser;
        private string $apiPassword;
        private string $apiClientId;
        private string $apiClientSecret;
        private string $baseUrl;
        private string $tokenFile;
        private array $curl_options = [];
        private bool $debugMode = false;

        /** @var \CurlHandle|null */
        private $http_client = null;

        public function __construct(array $settings)
        {
            $this->apiUser         = (string) ($settings['username'] ?? '');
            $this->apiPassword     = (string) ($settings['password'] ?? '');
            $this->apiClientId     = (string) ($settings['api_client'] ?? '');
            $this->apiClientSecret = (string) ($settings['api_secret'] ?? '');
            $this->baseUrl         = !empty($settings['test-mode']) ? self::API_URL_SANDBOX : self::API_URL_PROD;
            $this->tokenFile       = __DIR__ . DS . (!empty($settings['test-mode']) ? 'token-test.data' : 'token.data');
            $this->debugMode       = !empty($settings['debug-mode']);

            $customFile = __DIR__ . DS . 'custom_curl_options.json';
            if (is_file($customFile)) {
                $options = json_decode((string) file_get_contents($customFile));
                if (is_array($options)) {
                    foreach ($options as $data)
                        if (isset($data->key, $data->value)) $this->curl_options[$data->key] = $data->value;
                }
            }
        }

        public function enableDebug(): void
        {
            $this->debugMode = true;
        }

        private function http()
        {
            if ($this->http_client) return $this->http_client;

            $this->http_client = curl_init();
            curl_setopt($this->http_client, CURLOPT_HEADER, 0);
            curl_setopt($this->http_client, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($this->http_client, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($this->http_client, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($this->http_client, CURLOPT_CONNECTTIMEOUT, $this->connect_timeout);
            foreach ($this->curl_options as $key => $value) curl_setopt($this->http_client, $key, $value);

            return $this->http_client;
        }

        public static function isJson($string): bool
        {
            if (!is_string($string)) return false;
            json_decode($string);

            return json_last_error() === JSON_ERROR_NONE;
        }

        private static function redact($data)
        {
            if (is_object($data)) $data = json_decode(json_encode($data), true);
            if (!is_array($data)) return $data;

            foreach ($data as $key => $value) {
                if (is_string($key) && in_array(strtolower($key), self::SECRET_KEYS, true)) $data[$key] = '***';
                elseif (is_array($value)) $data[$key] = self::redact($value);
            }

            return $data;
        }

        private function log(string $action, $request, $response): void
        {
            if (!$this->debugMode || !$this->logger) return;
            ($this->logger)($action, self::redact($request), self::redact($response));
        }

        /**
         * @throws Exception
         */
        public function request($url = '', $params = [], $method = 'POST')
        {
            $this->error = '';
            $headers     = [];
            $urlFull     = $url;
            $body        = $params;

            if ($method === 'GET' && !empty($params)) {
                $urlFull .= (str_contains($urlFull, '?') ? '&' : '?') . http_build_query($params);
                $body = [];
            }

            $token = null;
            if (!str_starts_with($url, '/oauth/v2/token')) $token = $this->get_token();

            if (!empty($body)) {
                $body = json_encode($body);
                $headers['Content-Type'] = 'application/json';
            } else
                $body = '';

            if (!empty($token) && is_string($token)) $headers['Authorization'] = 'Bearer ' . $token;

            return $this->execute($url, $urlFull, strtoupper($method), $body, $headers, $params);
        }

        /**
         * Uploads one file as multipart/form-data (Regtown accepts a single file per request, field "file").
         *
         * @throws Exception
         */
        public function upload(string $url, string $path, string $postName, string $mimeType, string $field = 'file')
        {
            $this->error = '';
            if (!is_file($path) || !is_readable($path)) throw new Exception('File not readable');

            $token = $this->get_token();
            $headers = [];
            if (!empty($token) && is_string($token)) $headers['Authorization'] = 'Bearer ' . $token;

            // No Content-Type header: curl adds the multipart boundary itself.
            return $this->execute($url, $url, 'POST', [$field => new \CURLFile($path, $mimeType, $postName)], $headers,
                ['file' => $postName, 'type' => $mimeType, 'size' => filesize($path)]);
        }

        /**
         * @param array|string $body
         * @throws Exception
         */
        private function execute(string $url, string $urlFull, string $method, $body, array $headers, $logBody)
        {
            $ch = $this->http();
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_URL, $this->baseUrl . $urlFull);

            $send = [];
            foreach ($headers as $name => $value) $send[] = $name . ': ' . $value;
            curl_setopt($ch, CURLOPT_HTTPHEADER, $send);

            $raw = curl_exec($ch);
            if ($raw === false) {
                $this->error = curl_error($ch);
                $this->log($url, ['method' => $method, 'url' => $urlFull, 'body' => $logBody], ['curl_error' => $this->error]);
                throw new Exception($this->error ?: 'Connection error');
            }

            $response = self::isJson($raw) ? json_decode($raw) : $raw;
            $this->log($url, ['method' => $method, 'url' => $urlFull, 'body' => $logBody], $response);

            if (is_object($response) && isset($response->status) && !$response->status) {
                $msg = $response->message ?? $response->detail ?? 'UNKNOWN MESSAGE';
                $this->error = (string) $msg;
                throw new Exception($this->error);
            }

            return $response;
        }

        /**
         * Returns an access token string, the raw OAuth error object, or false.
         *
         * @throws Exception
         */
        public function get_token($force_refresh = false, $force_new_token = false)
        {
            $stored = is_file($this->tokenFile) ? json_decode((string) file_get_contents($this->tokenFile)) : null;

            if (!$force_refresh && !$force_new_token && isset($stored->created_at, $stored->expires_in, $stored->access_token)
                && ($stored->created_at + $stored->expires_in) > time())
                return $stored->access_token;

            $res = null;
            if (!$force_new_token && ($force_refresh || !empty($stored->refresh_token))) {
                try {
                    $res = $this->request('/oauth/v2/token', [
                        'refresh_token' => $stored->refresh_token ?? '',
                        'client_id'     => $this->apiClientId,
                        'client_secret' => $this->apiClientSecret,
                        'grant_type'    => 'refresh_token',
                    ], 'GET');
                } catch (Exception $e) {
                    $res = null;
                }
            }

            if (is_null($res)) {
                try {
                    $res = $this->request('/oauth/v2/token', [
                        'username'      => $this->apiUser,
                        'password'      => $this->apiPassword,
                        'client_id'     => $this->apiClientId,
                        'client_secret' => $this->apiClientSecret,
                        'grant_type'    => 'password',
                    ], 'GET');
                } catch (Exception $e) {
                    return false;
                }
            }

            if (!is_object($res)) return false;
            if (!empty($res->error)) return $res;

            if (isset($res->access_token)) {
                $res->created_at = time();
                @file_put_contents($this->tokenFile, json_encode($res, JSON_PRETTY_PRINT), LOCK_EX);

                return $res->access_token;
            }

            return false;
        }
    }
