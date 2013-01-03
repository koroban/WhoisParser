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
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * Template for .INT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Int extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/organisation:(?>[\x20\t]*)(.*?)(?=contact:)/is', 
            2 => '/contact:(?>[\x20\t]*)administrative(.*?)(?=contact)/is', 
            3 => '/contact:(?>[\x20\t]*)technical(.*?)(?=nserver)/is', 
            4 => '/nserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address'), 
            2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/nserver:(?>[\x20\t]*)([a-z0-9\.]*) [a-z0-9\.\:]*/im' => 'nameserver', 
                    '/nserver:(?>[\x20\t]*)[a-z0-9\.]* ([a-z0-9\.\:]*)/im' => 'ips', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'created'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/but this server does not have/i';
}