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
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
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
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
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
        
        if ($send !== strlen($lookupString . "\r\n")) {
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
        $proxyConfig = $this->getProxyConfig();
        
        if(is_array($proxyConfig)) {
            $this->sock = $this->connectToProxy($proxyConfig, $config);
        }
        else {
            $this->sock = @stream_socket_client('tcp://' . $config['server'] . ':' . $config['port'], $errno, $errstr, 30);
        }
        
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
    
        /**
     * Connects to proxy
     *
     * @throws WriteErrorException
     * @throws ConnectErrorException
     * @param  array $proxyConfig
     * @param  array $config
     * @return resource
     */
    private function connectToProxy(array $proxyConfig, array $config)
    {   
        $proxyURL = $proxyConfig['scheme'] . $proxyConfig['host'];
        if (isset($proxyConfig['port'])) {
            $proxyURL .= ':' . $proxyConfig['port'];
        } elseif ('http://' == substr($proxyURL, 0, 7)) {
            $proxyURL .= ':80';
        } elseif ('https://' == substr($proxyURL, 0, 8)) {
            $proxyURL .= ':443';
        }
        // http:// and https:// is not supported in proxy, replace it with tcp:// and ssl://
        $proxyURL = str_replace(array('http://', 'https://'), array('tcp://', 'ssl://'), $proxyURL);
            
        if (strpos($proxyURL, 'ssl://') !== false && ! extension_loaded('openssl')) {
            throw \Novutec\WhoisParser\AbstractException::factory('ConnectError', 'Openssl extension must be enabled to use a proxy over https');
        }
                       
        $socket = @stream_socket_client($proxyURL, $errno, $errstr, 30);
            
        if (! is_resource($socket)) {
            throw \Novutec\WhoisParser\AbstractException::factory('ConnectError', 'Unable to connect to proxy ' .
                    $proxyConfig['scheme'] . $proxyConfig['host'] . ':' . $proxyConfig['port']);
        }
            
        $parsed_socket = parse_url('tcp://' . $config['server']);
        
        if (isset($parsed_socket['port'])) {
            $config['port'] = $parsed_socket['port'];
        }
            
        $request = array();
        $request[] = 'CONNECT ' . $config['server'] . ':' . $config['port'] . ' HTTP/1.1';  
        $request[] = 'Host: ' . $proxyConfig['host'];
        $request[] = 'Proxy-Connection: keep-alive';
            
        if (! empty($proxyConfig['username']) && ! empty($proxyConfig['password'])) {
            $auth = $proxyConfig['username'] . ':' . $proxyConfig['password'];
            $auth = base64_encode($auth);
            $request[] = 'Proxy-Authorization: Basic ' . $auth;
        }
        
        $send = fwrite($socket, implode("\r\n", $request) . "\r\n\r\n");
            
        if ($send !== strlen(implode("\r\n", $request) . "\r\n\r\n")) {
            throw \Novutec\WhoisParser\AbstractException::factory('WriteError', 'Error while sending data via proxy(' .
                $send . '/' . strlen($lookupString . "\r\n") . ')');
        }

        return $socket;
    }    
    
    /**
     * Returns configuration for proxy if it's set, and false if it isn't set
     *
     * @return array|false Returns an associative array on success, and FALSE on failure.
     */
    private function getProxyConfig()
    {
        $proxyIni = dirname(dirname(__FILE__)) . '/Config/proxy.ini';
        // suppress a warning if proxy file doesn't exist
        if (@is_file($proxyIni)) {
            $proxyList = parse_ini_file($proxyIni, true);
            if(is_array($proxyList))
                return $this->getRandomProxy($proxyList);
        }
        // there is no proxy file or parsing ini file failed
        return false;
    }
    
    /**
     * Returns random configuration for proxy, and false if there is no valid configuration
     *
     * @param  array $proxyList
     * @return array|false Returns an associative array on success, and FALSE on failure.
     */
    private function getRandomProxy(array $proxyList) {
        $i = count($proxyList);
        // check if random configuration is valid, and repeat if it's not
        while($i--) {
            $randKey = array_rand($proxyList);
            $proxyConfig = $proxyList[$randKey];
            // return configuration only if basic options are set
            if (! empty($proxyConfig['enabled']) && $proxyConfig['enabled'] == 1 && ! empty($proxyConfig['port'])
                && ! empty($proxyConfig['host']) && ! empty($proxyConfig['scheme'])) {
                    return $proxyConfig;
            }
            unset($proxyList[$randKey]);
        }
        return false;
    }
}
