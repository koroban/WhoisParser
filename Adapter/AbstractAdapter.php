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
 * WhoisParser AbstractAdapter
 * 
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
     * @return mixed
     */
    public static function factory($type = 'socket')
    {
        if (file_exists(__DIR__ . '/' . ucfirst($type) . '.php')) {
            include_once __DIR__ . '/' . ucfirst($type) . '.php';
            $classname = 'Novutec\WhoisParser\\' . ucfirst($type);
            return new $classname();
        } else {
            return null;
        }
    }
}