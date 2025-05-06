<?php header('Content-Type: application/xhtml+xml'); ?><?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>formattie</title>
 </head>
 <body>
  <form action="/" method="POST">
   <a href="/" target="_blank">new tab</a><br/>
   <textarea id="content" name="content" rows="15" cols="80"><?php
if (isset($_POST['content'])) {
    $_POST['content'] = ltrim($_POST['content']);
    if (strpos($_POST['content'], ']]>') === false) {
        echo '<![CDATA[' . $_POST['content'] . ']]>';
    } else {
        echo htmlspecialchars($_POST['content']);
    }
}
?></textarea>
   <br/>
   <input type="submit" value="Submit"/>
   <input type="button" value="Clear" onclick="javascript:document.getElementById('content').value='';"/>
   <label><input type="checkbox" name="fixJsonEscaping"/> Fix JSON escaping</label>
  </form>
<?php
    if (isset($_POST['content'])) {
        $content = $_POST['content'];
        if (isset($_POST['fixJsonEscaping'])) {
            $content = str_replace(
                array('\n', '\\"', '\\/'),
                array("\n", '"', '/'),
                $content
            );
        }

        if (preg_match('#^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[A-Z]{0,4}#', $content)) {
            $content = strtotime($content);
        }

        if (is_numeric($content) && strlen(trim($content)) <= 13) {
            //unix timestamp
            $content = trim($content);
            if (strlen($content) === 13) {
                //milliseconds
                $content = $content / 1000;
            }
            $nice = 'UTC:   ' . gmdate('c', $content) . "\n"
                . 'Local: ' . date('c', $content);

            echo '<table>'
                . '<caption>Unix timestamp</caption>'
                . '<tr><th colspan="2" align="left">Timestamp</th>'
                . '<td><tt>' . $content . '</tt></td></tr>'
                . '<tr><th colspan="2" align="left">UTC date</th>'
                . '<td><tt>' . gmdate('c', $content) . '</tt></td></tr>'
                . '<tr><th>Local date</th>'
                . '<td>' . date('T P, e') . '</td>'
                . '<td><tt>' . date('c', $content) . '</tt></td></tr>'
            . '</table>';

        } else if (strpos(substr($content, 0, 10), '://') !== false
            || substr($content, 0, 7) == 'mailto:'
        ) {
            //URL
            $parts = parse_url($content);
            if (isset($parts['path'])) {
                $parts['path'] = urldecode($parts['path']);
            }
            if (isset($parts['query'])) {
                parse_str($parts['query'], $queryparts);
                $parts['query'] = $queryparts;
            }
            $nice = var_export($parts, true);
            echo '<pre>' . htmlspecialchars($nice) . '</pre>';

        } else if ($content[0] == '{' || $content[0] == '[') {
            //json
            $data = json_decode($content);
            if ($data === null) {
                echo '<p class="error">JSON error: ' . json_last_error_msg() . '</p>';
            }
            $nice = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            //to make it easier to copy values from the pretty print
            $noquotes = str_replace(['\\"', '\\\\'], ['"', '\\'], $nice);
            echo '<h2 id="json">Pretty JSON</h2>';
            echo '<pre>' . htmlspecialchars($noquotes) . '</pre>';

        } else if (strpos(substr($content, 0, 64), ':{') !== false) {
            //serialized php variable
            $nice = var_export(unserialize($content), true);

        } else if (strpos(substr($content, 0, 512), '.') !== false
            && preg_match('#^[a-zA-Z0-9+/=.]+$#', substr($content, 0, 512))
        ) {
            //JWT
            $parts = explode('.', $content);
            $jose = base64_decode($parts[0]);
            $isJwt = false;
            if ($jose === false) {
                echo '<p class="error">Cannot base64-decode JOSE header.</p>';
            } else {
                $joseData = json_decode($jose);
                if ($joseData === null) {
                    echo '<p class="error">JSON error: ' . json_last_error_msg() . '</p>';
                } else {
                    $nice = json_encode($joseData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

                    //to make it easier to copy values from the pretty print
                    $noquotes = str_replace(['\\"', '\\\\'], ['"', '\\'], $nice);
                    echo '<h2 id="jwt">JWT JOSE header</h2>';
                    echo '<pre>' . htmlspecialchars($noquotes) . '</pre>';

                    $isJwt = isset($joseData->typ) && $joseData->typ == 'JWT';
                }
            }

            if ($isJwt) {
                $jwt = base64_decode($parts[1]);
                if ($jwt === false) {
                    echo '<p class="error">Cannot base64-decode JWT contents.</p>';
                } else {
                    $jwtData = json_decode($jwt);
                    if ($jwtData === null) {
                        echo '<p class="error">JSON error: ' . json_last_error_msg() . '</p>';
                    } else {
                        $nice2 = json_encode($jwtData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                        $nice .= "\n" . $nice2;

                        //to make it easier to copy values from the pretty print
                        $noquotes = str_replace(['\\"', '\\\\'], ['"', '\\'], $nice2);
                        echo '<h2 id="jwt-data">JWT data</h2>';
                        echo '<pre>' . htmlspecialchars($noquotes) . '</pre>';
                    }
                }
            }

        } else {
            //xml
            $sub = substr($content, 0, 60);
            if (strpos($sub, 'version=\"1.0\"') !== false) {
                //escaped string copied from e.g. firebug
                $content = str_replace(
                    array('\"', '\/', '\n'),
                    array('"', '/', "\n"),
                    $content
                );
            } else if (strpos($sub, '<' . '?xml ') === false
                && strpos($sub, '&lt;?xml ') !== false
            ) {
                // encoded XML
                $content = htmlspecialchars_decode($content);
            }
            $descriptorspec = array(
                0 => array('pipe', 'r'),//stdin
                1 => array('pipe', 'w'),//stdout
                2 => array('pipe', 'w') //stderr
            );
            $process = proc_open('xmllint --recover --format -', $descriptorspec, $pipes);
            if (!is_resource($process)) {
                die(
                    '<div class="alert alert-error">'
                    . 'Cannot open process to execute xmllint'
                    . '</div>'
                );
            }

            fwrite($pipes[0], $content);
            fclose($pipes[0]);

            $nice = stream_get_contents($pipes[1]);
            fclose($pipes[1]);

            $errors = stream_get_contents($pipes[2]);
            fclose($pipes[2]);

            $retval = proc_close($process);

            if ($retval != 0) {
                echo '<div style="border:1px solid red;">Error> ' . htmlspecialchars($errors) . '</div>';
            }

            require_once __DIR__ . '/../vendor/autoload.php';
            $geshi = new \GeSHi($nice, 'xml');
            //$geshi->enable_line_numbers(GESHI_NORMAL_LINE_NUMBERS);
            //$geshi->set_header_type(GESHI_HEADER_DIV);

            echo '<pre>' . $geshi->parse_code() . '</pre>';
            echo 'Size: ' . number_format(strlen($content) / 1024, 2) . 'kiB';
        }

        echo '<hr/>';
        if (strpos($nice, ']]>') === false) {
            $encoded = '<![CDATA[' . $nice . ']]>';
        } else {
            $encoded = htmlspecialchars($nice);
        }
        echo '<textarea rows="10" cols="80">' . $encoded . '</textarea>';
    }
?>
  <script type="text/javascript">
    var content = document.getElementById('content');
    content.focus();
    if (content.value == '') {
        document.execCommand('paste');
    }
  </script>
 </body>
</html>
