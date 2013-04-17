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
 * Template for .ST
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_St extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            2 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=name servers)/is', 
            3 => '/name servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrar:(?>[\x20\t]*)(.*?)$/im' => 'registrar:name', 
                    '/creation Date:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/updated Date:(?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/contact:(?>[\x20\t]*)(.*?)$/im' => 'registrar:email'), 
            2 => array('/owner:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:organization', 
                    '/^(?>[\x20\t]*)contact:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:name', 
                    '/address:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:address', 
                    '/city:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:city', 
                    '/country:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:country'), 
            3 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found/i';
}