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
 * Template for .DZ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Dz extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Contact administratif#(?>[\. ]*)(.*?)(?=Contact technique)/is', 
            2 => '/Contact technique#(?>[\. ]*)(.*?)(?=-----------|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Organisme administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Adresse contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:address', 
                    '/Telephone contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Fax contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/Mail contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/^Contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Organisme technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Adresse contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:address', 
                    '/Telephone contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Fax contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/Mail contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:email', 
                    '/Registrar#(?>[\. ]*)(.+)$/im' => 'registrar:name', 
                    '/Date de creation#(?>[\. ]*)(.+)$/im' => 'created'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/NO OBJECT FOUND/i';
}