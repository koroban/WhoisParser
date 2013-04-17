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
    protected $blocks = array(1 => '/contact administratif#(?>[\. ]*)(.*?)(?=contact technique)/is', 
            2 => '/contact technique#(?>[\. ]*)(.*?)(?=-----------|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:name', 
                    '/organisme administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/adresse contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:address', 
                    '/telephone contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/fax contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/mail contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:name', 
                    '/organisme technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/adresse contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:address', 
                    '/telephone contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/mail contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:email', 
                    '/registrar#(?>[\. ]*)(.+)$/im' => 'registrar:name', 
                    '/date de creation#(?>[\. ]*)(.+)$/im' => 'created'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/NO OBJECT FOUND/i';
}