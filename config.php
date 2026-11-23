<?php
return [
    'meta' => [
        'name' => 'Regtown',
        'version' => '1.0.1',
        'logo' => 'regtown.png',
    ],
    'settings' => [
        // whois-types : If it is desired to indicate that (registrant, administrative, technical, billing) communication types are supported in the module, "true" must be defined.
        'whois-types' => true,
        'username' => '',
        'password' => '',
        'api_client' => '',
        'api_secret' => '',
        'test-mode' => 0,
        'debug-mode' => 0,
        'adp' => false,
        'cost-currency' => 4,
    ]
];
