<?php

$host = 'http://127.0.0.1:8787/verify';

$result = '';
$signature = '';
$data = '';
$signing_key = 'my secret symmetric key';

$path = $_POST['path'] ?? '/relieved-raven-af417dbb-local/ap-ds-01.png';
$width = $_POST['width'] ?? '300';
$height = $_POST['height'] ?? '200';

if ($_POST) {
    $path = parse_url($path, PHP_URL_PATH);
    $params = array_filter([
        'width' => $width,
        'height' => $height
    ]);

    $paramString = http_build_query($params);
    $data = $path . '#?' . $paramString;

    $signature = base64_encode(hash_hmac(
        'sha256',
        $data,
        $signing_key
    ));

    $result = $host . $path . '?' . $paramString . '&s=' . $signature;
}
?>
<!doctype html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta
            name="viewport"
            content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0"
        >
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <title>Document</title>
        <style>
          :root {
            font-family: sans-serif;
            box-sizing: border-box;
          }

          .app {
            display: grid;
            grid-template-columns: 1fr [content-start] min(80%, 800px) [content-end] 1fr;
          }

          .app > * {
            grid-column: content;
          }

          label {
            display: block;
          }

          input {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 0.5em;
            width: 100%;
            max-width: 600px;
          }

          .stack > * + * {
            margin-top: 1rem;

          }

          button {
            padding: 0.5em 1em;
            margin-top: 2em;
            border-radius: 3px;
            appearance: none;
            background-color: cornflowerblue;
            border: 1px solid transparent;
            font-family: inherit;
            color: #fff;
            font-size: 0.875rem;
          }

          pre {
            background-color: #e8e8e8;
            padding: 1rem;
            border-radius: 4px;
          }

        </style>
    </head>
    <body>
        <div class="app">

            <h1 class="text-xl font-bold">Request signing</h1>

            <form action="/" method="POST">
                <div class="stack">

                    <div>
                        <label for="path">Path</label>
                        <input type="text" name="path" value="<?php echo $path; ?>" />
                    </div>
                    <div>
                        <label for="width">Width</label>
                        <input type="text" name="width" value="<?php echo $width; ?>" />
                    </div>
                    <div>
                        <label for="height">Height</label>
                        <input type="text" name="height" value="<?php echo $height; ?>" />
                    </div>
                </div>

                <div>
                    <div>
                        <h2>Test URL</h2>
                        <a href="<?php echo $result; ?>" target="_blank"><?php echo $result; ?></a>
                    </div>
                    <pre><?php echo $data; ?></pre>
                    <pre><?php echo $signature; ?></pre>
                    <pre><?php echo base64_decode($signature); ?></pre>
                    <input type="text">
                </div>

                <button type="submit">Submit</button>
            </form>
        </div>
    </body>
</html>