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
 * Template for .UG
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ug extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)\n\n/is', 
            2 => '/\n\nAdmin Contact:(?>[\x20\t]*)(.*?)(?=Tech Contact:)/is', 
            3 => '/\n\nTech Contact:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Expiry:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/Updated:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/Admin Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/NIC:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:admin:city', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone'), 
            3 => array('/Tech Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/NIC:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:tech:city', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for/i';
}