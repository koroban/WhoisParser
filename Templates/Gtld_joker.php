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
 * Template for IANA #113
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_joker extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/owner:(?>[\x20\t]*)(.*?)(?=contact-hdl)/is', 
            2 => '/contact-hdl:(?>[\x20\t]*)(.*?)(?=contact-hdl|source)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^owner:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^postal-code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^owner-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^admin-c:(?>[\x20\t]*)(.+) .+$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+) .+$/im' => 'network:contacts:tech', 
                    '/^billing-c:(?>[\x20\t]*)(.+) .+$/im' => 'network:contacts:billing'), 
            2 => array('/^contact-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/^postal-code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone'));
}