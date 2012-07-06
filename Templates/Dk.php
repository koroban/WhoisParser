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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * Template for Dk
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Dk extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant(?>[\x20\t\r\n]*)(.*?)(?=Administrator)/is', 
            3 => '/Administrator(?>[\x20\t\r\n]*)(.*?)(?=Nameservers)/is', 
            4 => '/Nameservers(?>[\x20\t\r\n]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^Handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone'), 
            3 => array('/^Handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone'), 
            4 => array('/^Hostname:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for the selected source/i';
}