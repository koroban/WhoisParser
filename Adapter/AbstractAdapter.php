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
 * @namespace Novutec\WhoisParser\Adapter
 */
namespace Novutec\WhoisParser\Adapter;

/**
 * WhoisParser AbstractAdapter
 * 
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractAdapter
{

    /**
     * Is successfully connected to the whois server?
     *
     * @var boolean
     * @access protected
     */
    protected $connected = false;

    /**
     * Resource handler for whois server
     *
     * @var resource
     * @access protected
     */
    protected $sock = false;

    protected $proxyConfig = null;


    public function __construct($proxyConfig)
    {
        $this->proxyConfig = $proxyConfig;
    }

    /**
     * Send data to whois server
     * 
     * @param  object $query
     * @param  array $config
     * @return string
     */
    abstract public function call($query, $config);

    /**
     * Creates an adapter by type
     * 
     * Returns a adapter object, if not null.
     * Socket or HTTP, default is socket.
     * 
     * @param  string $type
     * @param string|null $proxyConfig
     * @param string|null $customNamespace
     * @return AbstractAdapter
     */
    public static function factory($type = 'socket', $proxyConfig = null, $customNamespace = null)
    {
        $obj = null;
        // Ensure the custom namespace ends with a \
        $customNamespace = rtrim($customNamespace, '\\') .'\\';
        if ((strpos($type, '\\') !== false) && class_exists($type)) {
            $obj = new $type($proxyConfig);
        } elseif ((strlen($customNamespace) > 1) && class_exists($customNamespace . ucfirst($type))) {
            $class = $customNamespace . ucfirst($type);
            $obj = new $class($proxyConfig);
        } elseif (class_exists('Novutec\WhoisParser\Adapter\\'. ucfirst($type))) {
            $class = 'Novutec\WhoisParser\Adapter\\' . ucfirst($type);
            $obj = new $class($proxyConfig);
        }
        return $obj;
    }
}