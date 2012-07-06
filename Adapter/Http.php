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
 * WhoisParser Http Adapter
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Http extends AbstractAdapter
{

    /**
     * Send data to whois server
     * 
     * @param  string $query
     * @param  array $config
     * @return string
     */
    public function call($query, $config)
    {
        $this->sock = curl_init();
        $url = $config['server'] . str_replace('%domain%', $query->idnFqdn, $config['format']);
        
        curl_setopt($this->sock, CURLOPT_USERAGENT, 'PHP');
        curl_setopt($this->sock, CURLOPT_TIMEOUT, 30);
        curl_setopt($this->sock, CURLOPT_HEADER, false);
        curl_setopt($this->sock, CURLOPT_SSL_VERIFYPEER, 'OFF');
        curl_setopt($this->sock, CURLOPT_SSLVERSION, 3);
        curl_setopt($this->sock, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->sock, CURLOPT_POST, false);
        
        curl_setopt($this->sock, CURLOPT_URL, $url);
        
        $rawdata = curl_exec($this->sock);
        
        curl_close($this->sock);
        
        return $rawdata;
    }
}