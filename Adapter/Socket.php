<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * WhoisParser Socket Adapter
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Socket extends AbstractAdapter
{

    /**
     * Send data to whois server
     *
     * @throws WriteErrorException
     * @throws ReadErrorException
     * @param  object $query
     * @param  array $config
     * @return string
     */
    public function call($query, $config)
    {
        $this->disconnect();
        $this->connect($config);
        
        stream_set_blocking($this->sock, 1);
        
        if (isset($query->tld) && ! isset($query->idnFqdn)) {
            $lookupString = str_replace('%domain%', $query->tld, $config['format']);
        } elseif (isset($query->ip)) {
            $lookupString = str_replace('%domain%', $query->ip, $config['format']);
        } elseif (isset($query->asn)) {
            $lookupString = str_replace('%domain%', $query->asn, $config['format']);
        } else {
            $lookupString = str_replace('%domain%', $query->idnFqdn, $config['format']);
        }
        
        $send = fwrite($this->sock, $lookupString . "\r\n");
        
        if ($send != strlen($lookupString . "\r\n")) {
            throw \Novutec\WhoisParser\AbstractException::factory('WriteError', 'Error while sending data (' .
                     $send . '/' . strlen($lookupString . "\r\n") . ')');
        }
        
        $read = $write = array($this->sock);
        $except = null;
        $rawdata = '';
        
        do {
            if (stream_select($read, $write, $except, 30) === false) {
                break;
            }
            
            $recv = stream_get_contents($this->sock);
            
            if ($recv === false) {
                throw \Novutec\WhoisParser\AbstractException::factory('ReadError', 'Could not read from socket.');
            }
            
            $rawdata .= $recv;
        } while ((! feof($this->sock)));
        
        return str_replace("\r", '', $rawdata);
    }

    /**
     * Creates and initiates a socket connection
     *
     * @throws ConnectErrorException
     * @param  array $config
     * @return void
     */
    private function connect($config)
    {
        $parsed_socket = parse_url('tcp://' . $config['server']);
        
        if (isset($parsed_socket['port'])) {
            $config['port'] = $parsed_socket['port'];
        }
        
        $errno = $errstr = null;
        $this->sock = @stream_socket_client('tcp://' . $config['server'] . ':' . $config['port'], $errno, $errstr, 30);
        
        if (! is_resource($this->sock)) {
            throw \Novutec\WhoisParser\AbstractException::factory('ConnectError', 'Unable to connect to ' .
                     $config['server'] . ':' . $config['port'] .
                     ' or missing configuration for this template.');
        }
        
        $this->connected = true;
    }

    /**
     * Disconnect a socket connection
     *
     * @return boolean
     */
    private function disconnect()
    {
        if ($this->connected) {
            return @stream_socket_shutdown($this->sock, STREAM_SHUT_RDWR);
        }
        
        return true;
    }
}