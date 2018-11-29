<?php

    $host = 'localhost';
    $port = '8080';
    $null = NULL;

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);
    socket_bind($socket, 0, $port);
    socket_listen($socket);
    $clients = array($socket);
    
    $array = [];

    while (true) {
        $changed = $clients;
        socket_select($changed, $null, $null, 0, 10);
        if (in_array($socket, $changed)) {
            $socket_new = socket_accept($socket);
            $clients[] = $socket_new;

            $header = socket_read($socket_new, 1024);
            perform_handshaking($header, $socket_new, $host, $port);

            $found_socket = array_search($socket, $changed);
            unset($changed[$found_socket]);
        }

        foreach ($changed as $changed_socket) {
            while(socket_recv($changed_socket, $buf, 1024, 0) >= 1) {
                $index = array_search($changed_socket, $clients);

                $received_text = unmask($buf);
                $txt_msg = json_decode($received_text);
                
                $check = false;

                if ($txt_msg == null) {
                    unset($clients[$index]);
                    unset($array[$index]);
                    send_to_client($array);
                    break 2;
                }

                foreach ($array as $key => $value) {
                    if ($value['name'] == $txt_msg->name) {
                        $check = true;
                        break;
                    }
                }

                if (!$check) {
                    $array[$index]['name'] = $txt_msg->name;
                    $array[$index]['number'] = $txt_msg->number;
                } else {
                    if ($txt_msg->number > 0) {
                        foreach ($array as $key => $value) {
                            $array[$key]['number'] = $value['number'] * $txt_msg->number;
                        }
                    }
                }

                send_to_client($array);
                break 2;
            }
            
            $buf = @socket_read($changed_socket, 1024, PHP_NORMAL_READ);
            if ($buf === false) {
                
                unset($clients[$index]);
                unset($array[$index]);
            }
        }
    }

    socket_close($socket);

    function send_to_client($a)
    {
        global $clients;

        $to_send = mask(json_encode($a));

        foreach ($clients as $changed_socket) {
            @socket_write($changed_socket, $to_send, strlen($to_send));
        }
        return true;
    }

//Unmask incoming framed message
function unmask($text) {
    $length = ord($text[1]) & 127;
    if($length == 126) {
        $masks = substr($text, 4, 4);
        $data = substr($text, 8);
    }
    elseif($length == 127) {
        $masks = substr($text, 10, 4);
        $data = substr($text, 14);
    }
    else {
        $masks = substr($text, 2, 4);
        $data = substr($text, 6);
    }
    $text = "";
    for ($i = 0; $i < strlen($data); ++$i) {
        $text .= $data[$i] ^ $masks[$i%4];
    }
    return $text;
}

//Encode message for transfer to client.
function mask($text)
{
    $b1 = 0x80 | (0x1 & 0x0f);
    $length = strlen($text);
    
    if($length <= 125)
        $header = pack('CC', $b1, $length);
    elseif($length > 125 && $length < 65536)
        $header = pack('CCn', $b1, 126, $length);
    elseif($length >= 65536)
        $header = pack('CCNN', $b1, 127, $length);
    return $header.$text;
}

//handshake new client.
function perform_handshaking($receved_header,$client_conn, $host, $port)
{
    $headers = array();
    $lines = preg_split("/\r\n/", $receved_header);
    foreach($lines as $line)
    {
        $line = chop($line);
        if(preg_match('/\A(\S+): (.*)\z/', $line, $matches))
        {
            $headers[$matches[1]] = $matches[2];
        }
    }

    $secKey = $headers['Sec-WebSocket-Key'];
    $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
    //hand shaking header
    $upgrade  = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
    "Upgrade: websocket\r\n" .
    "Connection: Upgrade\r\n" .
    "WebSocket-Origin: $host\r\n" .
    "WebSocket-Location: ws://$host:$port/demo/shout.php\r\n".
    "Sec-WebSocket-Accept:$secAccept\r\n\r\n";
    socket_write($client_conn,$upgrade,strlen($upgrade));
}
