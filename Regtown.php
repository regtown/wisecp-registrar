<?php
/**
 * Regtown registrar module for WISECP 5.
 */
    namespace WISECP\Modules\Registrars;

    use Exception;
    use RegistrarModule;
    use WISECP\Modules\Registrars\Regtown\ApiClient;

    include_once __DIR__ . DS . 'ApiClient.php';

    class Regtown extends RegistrarModule
    {
        private const DNSSEC_ALGORITHMS = [
            5  => 'RSA / SHA-1',
            7  => 'RSA / SHA-1, NSEC3',
            8  => 'RSA / SHA-256',
            10 => 'RSA / SHA-512',
            13 => 'ECDSA P-256 / SHA-256',
            14 => 'ECDSA P-384 / SHA-384',
            16 => 'EdDSA Curve25519',
        ];

        private const DNSSEC_DIGEST_TYPES = [2 => 'SHA-256', 4 => 'SHA-384'];

        public function __construct()
        {
            parent::__construct();

            $this->domains_import_list_paginate         = true;
            $this->domains_import_list_per_page_options = [10, 25, 50, 100];

            $settings = $this->config['settings'] ?? [];
            if (empty($settings['dns-algorithms']))   $this->config['settings']['dns-algorithms']   = self::DNSSEC_ALGORITHMS;
            if (empty($settings['dns-digest-types'])) $this->config['settings']['dns-digest-types'] = self::DNSSEC_DIGEST_TYPES;
        }



        private function initApi(): void
        {
            if ($this->api) return;

            $this->api = $this->make_client($this->config['settings'] ?? []);
        }

        private function make_client(array $settings): ApiClient
        {
            $password = $this->decode_str((string) ($settings['password'] ?? ''));
            $secret   = $this->decode_str((string) ($settings['api_secret'] ?? ''));
            if ($password !== '') $settings['password']   = $password;
            if ($secret !== '')   $settings['api_secret'] = $secret;

            $client         = new ApiClient($settings);
            $client->logger = fn($action, $req, $resp) => $this->save_log($action, $req, $resp);

            return $client;
        }

        private function text(string $key, string $fallback): string
        {
            return ((string) ($this->lang[$key] ?? '')) ?: $fallback;
        }

        /** @return array{0:string,1:string,2:string} ascii domain, sld, tld */
        private function domain_parts(): array
        {
            $sld    = (string) ($this->options['sld'] ?? $this->options['name'] ?? '');
            $tld    = (string) ($this->options['tld'] ?? '');
            $domain = (string) ($this->options['domain'] ?? ($sld && $tld ? $sld . '.' . $tld : ($this->service['name'] ?? '')));

            return [idn_to_ascii($domain, 0, INTL_IDNA_VARIANT_UTS46) ?: $domain, $sld, $tld];
        }

        private function domain(): string
        {
            return $this->domain_parts()[0];
        }

        /**
         * Runs an API request; on failure stores the message in $this->error and returns false.
         */
        private function call(string $url, $params = '', string $method = 'POST')
        {
            $this->initApi();

            try {
                return $this->api->request($url, $params, $method);
            } catch (Exception $e) {
                $this->error = $e->getMessage();
                return false;
            }
        }

        private function detail(string $domain = '')
        {
            if ($domain === '') $domain = $this->domain();

            $details = $this->call('/api/v2/domain/' . $domain, '', 'GET');
            if ($details === false) return false;

            if (!isset($details->data->attributes)) {
                $this->error = $this->text('domain-details-access-error', 'Domain details could not read!');
                return false;
            }

            return $details->data->attributes;
        }



        public function config_fields($settings = []): array
        {
            return [
                'username' => [
                    'type'        => 'text',
                    'name'        => $this->lang['fields']['username'] ?? 'Username',
                    'description' => $this->lang['desc']['username'] ?? '',
                    'value'       => $settings['username'] ?? '',
                ],
                'password' => [
                    'type'        => 'password',
                    'name'        => $this->lang['fields']['password'] ?? 'Password',
                    'description' => $this->lang['desc']['password'] ?? '',
                    'value'       => $settings['password'] ?? '',
                ],
                'api_client' => [
                    'type'        => 'text',
                    'name'        => $this->lang['fields']['api_client'] ?? 'Api Client Id',
                    'description' => $this->lang['desc']['api_client'] ?? '',
                    'value'       => $settings['api_client'] ?? '',
                ],
                'api_secret' => [
                    'type'        => 'password',
                    'name'        => $this->lang['fields']['api_secret'] ?? 'API Client Secret',
                    'description' => $this->lang['desc']['api_secret'] ?? '',
                    'value'       => $settings['api_secret'] ?? '',
                ],
                'test-mode' => [
                    'type'        => 'approval',
                    'name'        => $this->lang['fields']['test-mode'] ?? 'Test Mode',
                    'description' => $this->lang['desc']['test-mode'] ?? '',
                    'value'       => 1,
                    'checked'     => (bool) ($settings['test-mode'] ?? false),
                ],
                'debug-mode' => [
                    'type'        => 'approval',
                    'name'        => $this->lang['fields']['debug-mode'] ?? 'Debug Mode',
                    'description' => $this->lang['desc']['debug-mode'] ?? '',
                    'value'       => 1,
                    'checked'     => (bool) ($settings['debug-mode'] ?? false),
                ],
            ];
        }

        /**
         * Encrypts the secrets once, on save. Already encrypted values are left untouched.
         */
        public function check_fields(array $config = []): array
        {
            $set = [];
            foreach (['password', 'api_secret'] as $key) {
                $value = (string) ($config['settings'][$key] ?? '');
                if ($value === '' || $this->decode_str($value) !== '') continue;

                $set[$key] = $this->encode_str($value);
            }

            return $set ? ['settings' => $set] : [];
        }

        public function testConnection($config = []): bool
        {
            $settings = $config['settings'] ?? [];

            foreach (['username', 'password', 'api_client', 'api_secret'] as $key) {
                if (trim((string) ($settings[$key] ?? '')) === '') {
                    $this->error = $this->text('error-credentials', 'Please enter the API information.');
                    return false;
                }
            }

            try {
                $client = $this->make_client($settings);
                $token  = $client->get_token(false, true);
            } catch (Exception $e) {
                $this->error = $e->getMessage();
                return false;
            }

            if (is_object($token) && isset($token->error)) {
                $this->error = (string) ($token->error_description ?? $token->error);
                return false;
            }

            if (!$token) {
                $this->error = $client->error ?: $this->text('error-connection', 'The connection could not be established.');
                return false;
            }

            return true;
        }



        public function check($sld = null, $tlds = []): array
        {
            if ($sld == '' || !$tlds) {
                $this->error = $this->text('error2', 'Domain and extension information did not come.');
                return [];
            }

            if (!is_array($tlds)) $tlds = [$tlds];

            $sld     = idn_to_ascii($sld, 0, INTL_IDNA_VARIANT_UTS46) ?: $sld;
            $domains = [];
            $result  = [];
            foreach ($tlds as $tld) {
                $domains[$sld . '.' . $tld] = $tld;
                $result[$tld] = ['status' => 'unknown'];
            }

            $response = $this->call('/api/v2/domains/check', ['domains' => array_keys($domains), 'premium_check' => true]);
            if ($response === false) return [];

            if (empty($response->status) || !is_array($response->data ?? null)) {
                $this->error = $this->text('domain-check-error', 'Domain check available error!');
                return [];
            }

            foreach ($response->data as $item) {
                $name = idn_to_ascii((string) ($item->name ?? ''), 0, INTL_IDNA_VARIANT_UTS46) ?: (string) ($item->name ?? '');
                if (!isset($domains[$name])) continue;

                $status = (string) ($item->detail ?? 'unknown');
                $row    = ['status' => $status === 'not_available' ? 'unavailable' : $status];

                if ($row['status'] === 'available' && !empty($item->is_premium)) {
                    $row['premium']       = true;
                    $row['premium_price'] = ['amount' => (float) ($item->price ?? 0), 'currency' => $this->currency_id((string) ($item->currency ?? ''))];
                }

                $result[$domains[$name]] = $row;
            }

            return $result;
        }



        private function currency_id(string $code): int
        {
            $fallback = (int) ($this->config['settings']['cost-currency'] ?? 4);
            if ($code === '') return $fallback;

            \Helper::Load(['Money']);
            foreach (\Money::getCurrencies() as $currency)
                if (strcasecmp((string) $currency['code'], $code) === 0) return (int) $currency['id'];

            return $fallback;
        }

        /** Calling code (e.g. 90) to ISO region (TR); empty when unknown. */
        private static function region_of(string $callingCode): string
        {
            $callingCode = preg_replace('/\D+/', '', $callingCode);
            if ($callingCode === '' || !class_exists('\libphonenumber\PhoneNumberUtil')) return '';

            try {
                $region = \libphonenumber\PhoneNumberUtil::getInstance()->getRegionCodeForCountryCode((int) $callingCode);
            } catch (\Throwable $e) {
                return '';
            }

            return $region && $region !== 'ZZ' ? $region : '';
        }

        /** Regtown wants phone numbers as 90-532-1234567 (calling code, area code, 7 digits). */
        private static function dashed_phone(string $callingCode, string $number): string
        {
            $digits = preg_replace('/\D+/', '', $callingCode . $number);
            if ($digits === '') return '';
            if (strlen($digits) < 12) $digits = str_pad($digits, 12, '0', STR_PAD_LEFT);

            return substr($digits, 0, 2) . '-' . substr($digits, 2, 3) . '-' . substr($digits, -7);
        }

        /**
         * @param bool $update true for update-contact: dashed phone numbers and no empty fields, as the reseller panel sends them.
         */
        public static function toRegtownWhois($whois_data, bool $update = false): array
        {
            $c = (array) $whois_data;
            [$phoneCc, $phone] = RegistrarModule::whois_phone($c, 'Phone');
            [$faxCc, $fax]     = RegistrarModule::whois_phone($c, 'Fax');
            $country           = strtoupper(trim((string) ($c['Country'] ?? '')));

            $out = [
                'firstname'          => $c['FirstName'] ?? '',
                'lastname'           => $c['LastName'] ?? '',
                'address1'           => $c['AddressLine1'] ?? '',
                'address2'           => $c['AddressLine2'] ?? '',
                'city'               => $c['City'] ?? '',
                'state'              => $c['State'] ?? '',
                'country'            => $country,
                'email'              => $c['EMail'] ?? '',
                'fax'                => $update ? self::dashed_phone($faxCc, $fax) : $fax,
                'organization'       => $c['Company'] ?? '',
                'phone'              => $update ? self::dashed_phone($phoneCc, $phone) : $phone,
                'phone_country_code' => self::region_of($phoneCc) ?: ($country ?: 'TR'),
                'fax_country_code'   => self::region_of($faxCc ?: $phoneCc) ?: ($country ?: 'TR'),
                'tax_number'         => '',
                'tax_office'         => '',
                'www'                => '',
                'zip_code'           => $c['ZipCode'] ?? '',
            ];

            return $update ? array_filter($out, fn($v) => $v !== '' && $v !== null) : $out;
        }

        /**
         * .tr registrations identify the holder: citizen id for a person, tax office and number for a company.
         */
        private function holder_identity(array $registrant): array
        {
            $address = is_array($this->user['address'] ?? null) ? $this->user['address'] : [];
            $owner   = (int) ($this->service['owner_id'] ?? $this->user['id'] ?? 0);
            $account = $owner > 0 ? (\User::getInfo($owner, ['kind', 'identity', 'company_name', 'company_tax_office', 'company_tax_number']) ?: []) : [];

            $first = function (array $values): string {
                foreach ($values as $v) if (is_scalar($v) && trim((string) $v) !== '') return trim((string) $v);
                return '';
            };

            $company = $first([$registrant['Company'] ?? '', $address['company_name'] ?? '', $account['company_name'] ?? '']);
            $kind    = $first([$address['kind'] ?? '', $account['kind'] ?? '']);

            if ($kind !== '' ? $kind === 'corporate' : $company !== '') {
                return [
                    'tax_number' => preg_replace('/\D+/', '', $first([$this->docs['registrant_tax_number'] ?? '', $address['company_tax_number'] ?? '', $account['company_tax_number'] ?? ''])),
                    'tax_office' => $first([$this->docs['registrant_tax_office'] ?? '', $address['company_tax_office'] ?? '', $account['company_tax_office'] ?? '']),
                ];
            }

            $citizen = preg_replace('/\D+/', '', $first([$this->docs['registrant_citizen_id'] ?? '', $address['identity'] ?? '', $account['identity'] ?? '']));

            return $citizen !== '' ? ['meta' => [['type' => 'register', 'key' => 'citizenId', 'value' => $citizen]]] : [];
        }

        private static function nameserver_list(array $dns): array
        {
            $list = [];
            foreach ($dns as $ns) if ($ns) $list[] = ['ip' => '', 'name' => $ns];

            return $list;
        }

        public function register(): array|bool
        {
            $domain = $this->domain();
            $year   = (int) ($this->options['year'] ?? $this->service['period_time'] ?? 1) ?: 1;
            $whois  = $this->options['whois'] ?? [];

            $response = $this->call('/api/v2/domains/register', [
                'domain'   => $domain,
                'contact'  => self::toRegtownWhois($whois['registrant'] ?? $whois) + $this->holder_identity($whois['registrant'] ?? $whois),
                'duration' => $year,
                'dns'      => self::nameserver_list($this->options['dns'] ?? []),
                'domain_meta' => [],
            ]);
            if ($response === false) return false;

            if (empty($response->status)) {
                $this->error = (string) ($response->message ?? 'Registration failed');
                return false;
            }

            $config = !empty($response->id) ? ['config' => ['entityID' => $response->id]] : [];

            // Only an explicit "completed" means the domain is registered. Anything else (processing,
            // document_required, an application_id) is a pending application that registration_sync() follows up.
            if (($response->custom_status ?? '') === 'completed' && empty($response->application_id))
                return ['status' => 'SUCCESS'] + $config;

            // Documents the customer already submitted can go out right away; registration_sync() retries the rest.
            if ($this->docs) {
                $error = $this->error;
                $this->send_documents();
                $this->error = $error;
            }

            return ['status' => 'inprocess'] + $config;
        }

        /** Regtown limits: 5,000,000 bytes per file, 15 files per domain, one file per request. */
        private const DOC_MAX_SIZE  = 5000000;
        private const DOC_MAX_FILES = 15;

        /** Domain states in which Regtown still accepts (or expects) documents. */
        private const DOC_STATUSES = ['reserved', 'pending_approval', 'pending_registry'];

        /**
         * Sends the documents the customer submitted in WISECP ($this->docs, file fields only) to Regtown.
         * Idempotent: a file is skipped when Regtown already lists a document with the name we upload it under.
         *
         * @return array{sent:string[],failed:string[],rejected:string[]}|false false when the document list can not be read
         */
        private function send_documents(): array|false
        {
            $result = ['sent' => [], 'failed' => [], 'rejected' => []];

            $files = [];
            foreach ((array) $this->docs as $key => $path) {
                if (!is_string($path) || $path === '' || !is_file($path)) continue;
                $files[(string) $key] = $path;
            }

            $domain = $this->domain();
            $list   = $this->call('/api/v2/documents/get-list/' . $domain, '', 'GET');
            if ($list === false) {
                // Regtown answers "UNKNOWN MESSAGE" when nothing was uploaded yet.
                if ($this->error !== 'UNKNOWN MESSAGE') return false;
                $this->error = '';
                $remote = [];
            } else
                $remote = array_map(fn($item) => $item->attributes ?? $item, (array) ($list->data ?? []));

            $known = [];
            foreach ($remote as $doc) {
                $known[(string) ($doc->name ?? '')] = true;
                if (($doc->status ?? '') === 'rejected') $result['rejected'][] = (string) ($doc->name ?? $doc->id ?? '');
            }

            $count = count($remote);
            foreach ($files as $key => $path) {
                $mime = function_exists('mime_content_type') ? (string) @mime_content_type($path) : '';
                if ($mime !== 'application/pdf' && !str_starts_with($mime, 'image/')) {
                    $result['failed'][] = $key . ': ' . $this->text('error-doc-type', 'Only PDF and image files are accepted.');
                    continue;
                }

                $ext  = strtolower(pathinfo($path, PATHINFO_EXTENSION)) ?: ($mime === 'application/pdf' ? 'pdf' : substr($mime, 6));
                $name = preg_replace('/[^a-z0-9._-]+/i', '-', $key . '-' . $domain) . '.' . $ext;

                if (isset($known[$name])) continue;

                if (filesize($path) > self::DOC_MAX_SIZE) {
                    $result['failed'][] = $key . ': ' . $this->text('error-doc-size', 'The file is larger than 5 MB.');
                    continue;
                }
                if ($count >= self::DOC_MAX_FILES) {
                    $result['failed'][] = $key . ': ' . $this->text('error-doc-count', 'Maximum number of documents reached.');
                    continue;
                }

                $this->initApi();
                try {
                    $this->api->upload('/api/v2/documents/send/' . $domain, $path, $name, $mime);
                    $result['sent'][] = $key;
                    $count++;
                } catch (Exception $e) {
                    $result['failed'][] = $key . ': ' . $e->getMessage();
                }
            }

            return $result;
        }

        /**
         * Polled by WISECP for registrations that are still pending (e.g. waiting for documents or the registry).
         */
        public function registration_sync(): array|false
        {
            $attrs = $this->detail();
            if ($attrs === false) return false; // could not ask, keep waiting

            $status = (string) ($attrs->status ?? '');
            if ($status === 'active') {
                return [
                    'status'  => 'active',
                    'message' => '',
                    'endtime' => \DateManager::format('c', $attrs->expiry_date ?? ''),
                ];
            }

            if (in_array($status, ['cancelled', 'transfer_cancelled', 'transfer_error'], true))
                return ['status' => 'failed', 'message' => $this->domain() . ': ' . $status];

            $message = $status;
            if (in_array($status, self::DOC_STATUSES, true)) {
                $message = $this->text('docs-required', 'Waiting for Regtown: documents may be required, upload them in the Regtown panel.') . ' (' . $status . ')';
                $docs = $this->send_documents();
                if ($docs === false)
                    $message .= ' - ' . $this->error;
                else {
                    if ($docs['sent'])     $message .= ' - ' . $this->text('docs-sent', 'Documents sent') . ': ' . implode(', ', $docs['sent']);
                    if ($docs['rejected']) $message .= ' - ' . $this->text('docs-rejected', 'Documents rejected') . ': ' . implode(', ', $docs['rejected']);
                    if ($docs['failed'])   $message .= ' - ' . implode('; ', $docs['failed']);
                }
            }

            return ['status' => 'pending', 'message' => $message];
        }

        public function transfer(): array|bool
        {
            $response = $this->call('/api/v2/domain-transfer/demand', [
                'domain'    => $this->domain(),
                'auth_code' => $this->options['tcode'] ?? '',
            ]);
            if ($response === false) return false;

            if (empty($response->status)) {
                $this->error = (string) ($response->message ?? 'Transfer failed');
                return false;
            }

            return ['status' => 'SUCCESS', 'config' => ['entityID' => $response->id ?? '']];
        }

        public function renew(): array|bool
        {
            $year = (int) ($this->options['year'] ?? $this->service['period_time'] ?? 1) ?: 1;

            $renew = $this->call('/api/v2/domain/' . $this->domain() . '/renew?duration=' . $year, '', 'GET');

            return $renew !== false && !empty($renew->status);
        }



        /**
         * Live nameservers of a domain, empty slots dropped. Regtown returns five slots, most of them blank.
         *
         * @return string[]|false
         */
        private function live_nameservers(string $domain = ''): array|false
        {
            if ($domain === '') $domain = $this->domain();

            $response = $this->call('/api/v2/domain/' . $domain . '/get-dns', '', 'GET');

            // Some Regtown endpoints are addressed by the numeric domain id handed back at registration.
            $id = $this->options['config']['entityID'] ?? $this->service['options']['config']['entityID'] ?? '';
            if ($response === false && $id !== '' && $id !== null) $response = $this->call('/api/v2/domain/' . $id . '/get-dns', '', 'GET');
            if ($response === false) return false;

            $list = [];
            foreach ((array) ($response->dns_result ?? []) as $row) {
                $ns = strtolower(trim((string) ($row->nsName ?? '')));
                if ($ns !== '') $list[] = $ns;
            }

            return $list;
        }

        public function get_nameservers(): array|false
        {
            return $this->live_nameservers();
        }

        public function save_nameservers(array $dns): bool
        {
            $change = $this->call('/api/v2/domain/' . $this->domain() . '/change-dns', ['dns' => self::nameserver_list($dns)]);

            return $change !== false && !empty($change->status);
        }



        /** @return array<int,array{name:string,ip:string}>|false */
        private function sub_dns(): array|false
        {
            $response = $this->call('/api/v2/domain/' . $this->domain() . '/get-sub-dns', '', 'GET');
            if ($response === false) return false;

            $list = [];
            foreach ((array) ($response->dns_result ?? []) as $item)
                $list[] = ['name' => (string) ($item->name ?? ''), 'ip' => (string) ($item->ip ?? '')];

            return $list;
        }

        private function save_sub_dns(array $list): bool
        {
            $domain = $this->domain();
            $suffix = '.' . $domain;
            $rows   = [];
            foreach ($list as $item) {
                $name = (string) $item['name'];
                if (str_ends_with($name, $suffix)) $name = substr($name, 0, -strlen($suffix));
                $rows[] = ['name' => $name, 'ip' => (string) $item['ip']];
            }

            $change = $this->call('/api/v2/domain/' . $domain . '/change-sub-dns', ['dns' => $rows]);

            return $change !== false && !empty($change->status);
        }

        public function get_child_nameservers(): array|false
        {
            $list = $this->sub_dns();
            if ($list === false) return false;

            $result = [];
            foreach ($list as $i => $item) $result[$i + 1] = ['ns' => $item['name'], 'ip' => $item['ip']];

            return $result;
        }

        public function add_child_nameserver(string $ns, string $ip): array
        {
            $list = $this->sub_dns();
            if ($list === false) return [];

            foreach ($list as $item) {
                if ($item['name'] === $ns) {
                    $this->error = $this->text('custom-ns-exists-error', 'This custom name server exists!');
                    return [];
                }
            }

            $list[] = ['name' => $ns, 'ip' => $ip];

            return $this->save_sub_dns($list) ? ['ns' => $ns, 'ip' => $ip] : [];
        }

        public function save_child_nameserver(array $old, string $new_ns, string $new_ip): array
        {
            $oldNs = $old['ns'] ?? '';
            if (!$oldNs) {
                $this->error = $this->text('old-ns-access-error', 'Could not access old data!');
                return [];
            }

            $list = $this->sub_dns();
            if ($list === false) return [];

            foreach ($list as $i => $item)
                if ($item['name'] === $oldNs) $list[$i] = ['name' => $new_ns, 'ip' => $new_ip];

            return $this->save_sub_dns($list) ? ['ns' => $new_ns, 'ip' => $new_ip] : [];
        }

        public function delete_child_nameserver(string $ns, string $ip): bool
        {
            $list = $this->sub_dns();
            if ($list === false) return false;

            $list = array_values(array_filter($list, fn($item) => $item['name'] !== $ns));

            return $this->save_sub_dns($list);
        }



        private static function fromRegtownContact($c): array
        {
            $c = is_object($c) ? (array) $c : (array) $c;
            $first = (string) ($c['firstname'] ?? '');
            $last  = (string) ($c['lastname'] ?? '');

            return [
                'FirstName'    => $first,
                'LastName'     => $last,
                'Name'         => trim($first . ' ' . $last),
                'Company'      => (string) ($c['organization'] ?? ''),
                'EMail'        => (string) ($c['email'] ?? ''),
                'Phone'        => (string) ($c['phone'] ?? ''),
                'Fax'          => (string) ($c['fax'] ?? ''),
                'AddressLine1' => (string) ($c['address1'] ?? ''),
                'AddressLine2' => (string) ($c['address2'] ?? ''),
                'City'         => (string) ($c['city'] ?? ''),
                'State'        => (string) ($c['state'] ?? ''),
                'Country'      => (string) ($c['country'] ?? ''),
                'ZipCode'      => (string) ($c['zip_code'] ?? $c['zip'] ?? ''),
            ];
        }

        public function get_contacts(): array|false
        {
            $response = $this->call('/api/v2/domain/get-owner/' . $this->domain(), '', 'GET');
            if ($response === false) return false;

            $owner = $response->data ?? $response;
            $owner = $owner->attributes ?? $owner;
            if (!is_object($owner) || !isset($owner->email) && !isset($owner->firstname)) {
                $this->error = $this->text('domain-details-access-error', 'Domain details could not read!');
                return false;
            }

            // Regtown holds a single owner contact; it stands in for every role.
            $contact = self::fromRegtownContact($owner);

            return ['registrant' => $contact, 'administrative' => $contact, 'technical' => $contact, 'billing' => $contact];
        }

        public function save_contacts(array $whois): bool
        {
            $registrant = $whois['registrant'] ?? [];
            $pick       = fn(string $role) => self::toRegtownWhois($whois[$role] ?? $registrant, true);

            // Same roles the reseller panel updates; Regtown has no separate billing contact.
            $update = $this->call(
                sprintf('/api/v2/domain/%s/update-contact', $this->domain()),
                [
                    'owner'     => $pick('registrant'),
                    'admin'     => $pick('administrative'),
                    'technical' => $pick('technical'),
                ],
                'PATCH'
            );

            return $update !== false;
        }



        public function is_inactive(): bool
        {
            $attrs = $this->detail();
            if ($attrs === false) return false;

            return ($attrs->status ?? '') !== 'active';
        }

        public function get_transfer_lock(): string
        {
            $attrs = $this->detail();
            if ($attrs === false)
                throw new Exception($this->error ?: 'Failed to retrieve transfer lock status');

            return !empty($attrs->locked) ? 'active' : 'passive';
        }

        public function toggle_transfer_lock(string $status): bool
        {
            $toLocked = $status === 'enable';

            $attrs = $this->detail();
            if ($attrs === false) return false;
            if ($toLocked === !empty($attrs->locked)) return true;

            return $this->call('/api/v2/domain/' . $this->domain(), ['locked' => $toLocked], 'PATCH') !== false;
        }

        public function get_whois_privacy(): string
        {
            $details = $this->call('/api/v2/domain/get-privacy/' . $this->domain(), '', 'GET');
            if ($details === false)
                throw new Exception($this->error ?: 'Failed to retrieve whois privacy status');

            return !empty($details->privacy ?? $details->status) ? 'active' : 'passive';
        }

        public function toggle_whois_privacy(string $status): bool
        {
            $url = sprintf('/api/v2/domain/set-privacy/%s/%d', $this->domain(), $status === 'enable' ? 1 : 0);

            return $this->call($url, '', 'GET') !== false;
        }

        public function addon_create(array $addon): bool
        {
            if (($addon['addon_key'] ?? '') !== 'whois-privacy') return true;

            return $this->toggle_whois_privacy('enable');
        }

        public function addon_cancel(array $addon): bool
        {
            if (($addon['addon_key'] ?? '') !== 'whois-privacy') return true;

            return $this->toggle_whois_privacy('disable');
        }

        public function get_auth_code(): string|bool
        {
            $req = $this->call('/api/v2/domain-transfer/get-auth-code', ['domain' => $this->domain(), 'email' => 0], 'GET');
            if ($req === false) return false;

            return isset($req->detail) && $req->detail !== '' ? (string) $req->detail : true;
        }



        /**
         * DNSSEC availability is per extension: get-dns reports it, together with the fields Regtown accepts.
         *
         * @return string[]|false the accepted field names
         */
        private function dnssec_fields(): array|false
        {
            $response = $this->call('/api/v2/domain/' . $this->domain() . '/get-dns', ['only_dnssec_info' => 'true'], 'GET');
            if ($response === false || empty($response->dnssec_support)) {
                if ($response !== false) $this->error = '';
                $this->error = $this->error ?: $this->text('error-dnssec-unsupported', 'DNSSEC is not available for this domain extension.');
                return false;
            }

            $fields = (array) ($response->dnssec_fields ?? []);
            foreach (['algorithm' => ['dns-algorithms', self::DNSSEC_ALGORITHMS], 'digestType' => ['dns-digest-types', self::DNSSEC_DIGEST_TYPES]] as $field => [$setting, $labels]) {
                $allowed = array_keys((array) ($fields[$field]->options ?? []));
                if (!$allowed) continue;

                $keep = [];
                foreach ($allowed as $value) $keep[(int) $value] = $labels[(int) $value] ?? (string) $value;
                $this->config['settings'][$setting] = $keep;
            }

            return array_keys($fields);
        }

        public function get_dnssec_records(): array|false
        {
            if ($this->dnssec_fields() === false) return false;

            $response = $this->call('/api/v2/domain/' . $this->domain() . '/dnssec-records', '', 'GET');
            if ($response === false) {
                // Regtown answers "UNKNOWN MESSAGE" when the domain has no records yet.
                if ($this->error !== 'UNKNOWN MESSAGE') return false;
                $this->error = '';
                return [];
            }

            $list = [];
            foreach ((array) ($response->data ?? []) as $r) {
                if (empty($r->keyTag)) continue;
                $list[] = [
                    'identity'    => (string) $r->keyTag,
                    'digest'      => (string) ($r->digest ?? ''),
                    'key_tag'     => (string) $r->keyTag,
                    'digest_type' => (string) ($r->digestType ?? ''),
                    'algorithm'   => (string) ($r->algorithm ?? $r->alg ?? ''),
                ];
            }

            return $list;
        }

        public function add_dnssec_record($digest, $key_tag, $digest_type, $algorithm): bool
        {
            $fields = $this->dnssec_fields();
            if ($fields === false) return false;

            $data = array_intersect_key([
                'algorithm'  => $algorithm,
                'keyTag'     => $key_tag,
                'digestType' => $digest_type,
                'digest'     => $digest,
            ], array_flip($fields));

            $add = $this->call('/api/v2/domain/' . $this->domain() . '/dnssec-records', $data);

            return $add !== false;
        }

        public function delete_dnssec_record($digest, $key_tag, $digest_type, $algorithm, $identity = ''): bool
        {
            if ($this->dnssec_fields() === false) return false;

            $delete = $this->call('/api/v2/domain/' . $this->domain() . '/dnssec-records/' . ($identity !== '' ? $identity : $key_tag), '', 'DELETE');

            return $delete !== false;
        }



        public function suspend(): bool
        {
            return true;
        }

        public function unsuspend(): bool
        {
            return true;
        }

        public function cancel(): bool
        {
            return true;
        }



        public static function statusConvert($status): string
        {
            return match ($status) {
                'active'                                          => 'active',
                'expired', 'grace', 'redemption'                  => 'expired',
                'incoming_transfer', 'reserved', 'pending', 'pending_approval', 'pending_registry' => 'pending',
                'cancelled', 'transferred_away', 'transfer_cancelled' => 'cancelled',
                default                                           => 'unknown',
            };
        }

        public function sync(): array|false
        {
            $attrs = $this->detail();
            if ($attrs === false) return false;

            return [
                'creationtime' => \DateManager::format('c', $attrs->registration_date ?? ''),
                'endtime'      => \DateManager::format('c', $attrs->expiry_date ?? ''),
                'status'       => self::statusConvert($attrs->status ?? ''),
            ];
        }

        public function transfer_sync(): array|false
        {
            return $this->sync();
        }

        public function get_info(array $params = []): array|false
        {
            $domain = idn_to_ascii($params['domain'] ?? $this->domain(), 0, INTL_IDNA_VARIANT_UTS46) ?: ($params['domain'] ?? $this->domain());

            $attrs = $this->detail($domain);
            if ($attrs === false) return false;

            $info = [
                'creation_time' => \DateManager::format('c', $attrs->registration_date ?? ''),
                'end_time'      => \DateManager::format('c', $attrs->expiry_date ?? ''),
                'transferlock'  => !empty($attrs->locked),
            ];

            $error = $this->error;
            foreach (array_slice($this->live_nameservers($domain) ?: [], 0, 4) as $i => $ns) $info['ns' . ($i + 1)] = $ns;
            $this->error = $error;

            return $info;
        }



        /** Only domains in these Regtown states are offered on the import screen. */
        private const IMPORT_STATUSES = ['active', 'reserved', 'pending', 'pending_approval', 'pending_registry', 'incoming_transfer'];

        public function domains()
        {
            $perPage = (int) $this->domains_import_list_per_page ?: 10;
            $page    = max(1, (int) $this->domains_import_list_page);

            $data = $this->call('/api/v2/domains', [
                'page'     => $page - 1,
                'pageSize' => $perPage,
                'orderBy'  => 'id',
                'order'    => 'desc',
                'status'   => implode(',', self::IMPORT_STATUSES),
            ], 'GET');
            if ($data === false) return false;

            $this->domains_import_list_total        = (int) ($data->meta->total_result ?? 0);
            $this->domains_import_list_total_filter = 0;

            $result = [];
            foreach ((array) ($data->data ?? []) as $row) {
                $detail = $row->attributes ?? null;
                $domain = $detail->domain ?? '';
                if (!$domain) continue;

                $domain = (string) idn_to_utf8($domain, 0, INTL_IDNA_VARIANT_UTS46) ?: $domain;

                $orderId  = 0;
                $userData = [];
                $imported = \WDB::select('id,owner_id AS user_id')->from('users_products');
                $imported->where('type', '=', 'domain', '&&');
                $imported->where('name', '=', $domain);
                $imported = $imported->build() ? $imported->getAssoc() : false;
                if ($imported) {
                    $orderId  = $imported['id'];
                    $userData = \User::getData($imported['user_id'], 'id,full_name,company_name', 'array');
                }

                $result[] = [
                    'domain'        => $domain,
                    'creation_date' => isset($detail->registration_date) ? \DateManager::format('c', $detail->registration_date) : '',
                    'end_date'      => isset($detail->expiry_date) ? \DateManager::format('c', $detail->expiry_date) : '',
                    'order_id'      => $orderId,
                    'user_data'     => $userData,
                ];
            }

            return $result;
        }

        public function cost_prices($type = 'domain')
        {
            if ($type !== 'domain') {
                $this->error = $this->text('cost-only-domain-error', 'This method allow only domains.');
                return false;
            }

            \Helper::Load(['Products', 'Money']);

            $currencies = [];
            foreach (\Money::getCurrencies() as $systemCurrency) $currencies[$systemCurrency['code']] = $systemCurrency['id'];

            $costCid = (int) ($this->config['settings']['cost-currency'] ?? 4);
            $result  = [];
            $page    = 0;
            $max     = 0;

            while ($page <= $max) {
                $prices = $this->call('/api/v2/pricing?page=' . $page, '', 'GET');
                if ($prices === false) return false;

                $max = (int) ($prices->meta->max_page ?? 0);
                if (!is_array($prices->data ?? null)) {
                    $this->error = $this->text('error8', 'An error has occurred.');
                    return false;
                }

                foreach ($prices->data as $val) {
                    $attrs = $val->attributes ?? null;
                    if (!$attrs || !isset($attrs->domain_tld) || !isset($currencies[$attrs->currency ?? ''])) continue;

                    $from   = $currencies[$attrs->currency];
                    $amount = [
                        'register' => (float) ($attrs->register_amount ?? 0),
                        'transfer' => (float) ($attrs->transfer_amount ?? 0),
                        'renewal'  => (float) ($attrs->renew_amount ?? 0),
                    ];

                    foreach ($amount as $key => $value) {
                        if ($from != $costCid) $value = \Money::exChange($value, $from, $costCid);
                        $amount[$key] = (float) number_format((float) $value, 2, '.', '');
                    }

                    $result[$attrs->domain_tld] = $amount + ['currency' => $costCid];
                }

                $page++;
            }

            return $result;
        }
    }
