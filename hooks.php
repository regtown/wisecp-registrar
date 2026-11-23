<?php
/**
 * Regtown: premium domains renew at the premium price, not at the extension's standard renewal price.
 *
 * WISECP's availability result carries a single premium price (registration) and the renewal invoice
 * otherwise uses the TLD renewal price. Regtown renews a premium domain at the premium price, so the
 * renewal amount is replaced here with the live premium price (same conversion and markup as at checkout).
 * Any failure leaves the standard amount untouched.
 */

Hook::add('filter:domain.premium_renewal_price', 10, function (&$amount, $service = [], $tld = [], $target_currency = 0) {
    try {
        if (!is_array($service) || !is_array($tld)) return null;
        if (($tld['module'] ?? '') !== 'Regtown') return null;

        $domain = strtolower(trim((string) ($service['name'] ?? '')));
        if ($domain === '' || !str_contains($domain, '.')) return null;

        [$sld, $ext] = explode('.', $domain, 2);
        if ($sld === '' || $ext === '') return null;

        $price = \Cache::remember('Regtown', 'premium_renewal_' . md5($domain), 600, function () use ($sld, $ext, $domain) {
            $entry = \Registrar::check($sld, [$ext])[$domain] ?? [];
            if (empty($entry['premium']) || empty($entry['premium_price']['amount'])) return ['premium' => false];

            return [
                'premium'  => true,
                'amount'   => (float) $entry['premium_price']['amount'],
                'currency' => $entry['premium_price']['currency'] ?? 0,
            ];
        });

        if (!is_array($price) || empty($price['premium']) || $price['amount'] <= 0) return null;

        $renewal = \Registrar::premium_customer_price((float) $price['amount'], $price['currency'], (int) $target_currency);
        if ($renewal > 0) $amount = $renewal * max(1, (int) ($service['period_time'] ?? 1));
    } catch (\Throwable $e) {
        // Keep the standard renewal amount.
    }

    return null;
});

/**
 * Search results: show the premium price as the renewal price for Regtown premium domains.
 */
Hook::add('filter:domain.client_search_results', 10, function (&$response, $context = []) {
    try {
        if (!is_array($response) || !empty($context['transfer'])) return null;

        $ucid = (int) ($context['ucid'] ?? 0);
        $fix  = function ($entry) use ($ucid) {
            if (!is_array($entry) || empty($entry['premium']) || empty($entry['price_raw'])) return $entry;

            $tld = \Products::get_tld(ltrim((string) ($entry['tld'] ?? ''), '.'));
            if (($tld['module'] ?? '') !== 'Regtown') return $entry;

            $entry['renew_raw'] = $entry['price_raw'];
            $entry['renew']     = \Money::formatter_symbol($entry['price_raw'], $ucid);

            return $entry;
        };

        if (isset($response['primary'])) $response['primary'] = $fix($response['primary']);
        foreach ((array) ($response['suggestions'] ?? []) as $i => $entry) $response['suggestions'][$i] = $fix($entry);
    } catch (\Throwable $e) {
        // Keep the standard renewal display.
    }

    return null;
});
