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
 * Template for .LT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Lt extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)(?=Registrar:)/is', 
            2 => '/Registrar:(?>[\x20\t]*)(.*?)(?=Contact (name|organization))/is', 
            3 => '/Contact (name|organization):(?>[\x20\t]*)(.*?)(?=Contact (name|organization)|Nameserver)/is', 
            4 => '/Nameserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^Registered:(?>[\x20\t]*)(.+)$/im' => 'created'), 
            2 => array('/^Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Registrar website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/^Registrar email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            3 => array('/^Contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            4 => array('/^Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/available/i';
}