<?php

$verifyHost = 'http://127.0.0.1:8787';

$signing_key = 'my secret symmetric key';

$prefix = '/generate/';
$url = $_SERVER['REQUEST_URI'];
$pathname = parse_url($url, PHP_URL_PATH);
$query = parse_url($url, PHP_URL_QUERY);

if (str_starts_with($pathname, $prefix)) {
    echo $verifyHost . $pathname . '?' . $query;
    $pathname = '/verify/' .substr($pathname, strlen($prefix));
    $data = $pathname . '#?' . $query;

    $signature = base64_encode(hash_hmac(
        'sha256',
        $data,
        $signing_key
    ));

    $signature = str_replace('+', '-', $signature);

    $verifyUrl = $verifyHost . $pathname . '?'. $query . '&s=' . $signature;
    echo '<div><a target="_blank" href="' . $verifyUrl .'">' . $verifyUrl . '</a></div>';
}