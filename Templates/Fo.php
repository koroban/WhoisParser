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
 * Template for .FO
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Fo extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=contact)/is', 
            2 => '/contact:(?>[\x20\t]*)(.*?)(?=nserver)/is',
            3 => '/nserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'modified', 
                    '/^expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^org:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^street:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city',
                    '/^postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country',
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone',
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created'),
            3 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found./i';
}