<?php

$host = 'http://127.0.0.1:8787';

$result = '';
$signature = '';
$data = '';
$signing_key = 'my secret symmetric key';

$path = $_POST['path'] ?? '/relieved-raven-af417dbb-local/ap-ds-01.png';
$width = $_POST['width'] ?? '300';
$height = $_POST['height'] ?? '200';

$prefix = '/generate/';
$url = $_SERVER['REQUEST_URI'];
$pathname = parse_url($url, PHP_URL_PATH);
$query = parse_url($url, PHP_URL_QUERY);

if (str_starts_with($pathname, $prefix)) {
    $pathname = '/verify/' .substr($pathname, strlen($prefix));
    $data = $pathname . '#?' . $query;

    $signature = base64_encode(hash_hmac(
        'sha256',
        $data,
        $signing_key
    ));

    $verifyUrl = $host . $pathname . '?'. $query . '&s=' . $signature;
    echo '<a target="_blank" href="' . $verifyUrl .'">' . $verifyUrl . '</a>';
}