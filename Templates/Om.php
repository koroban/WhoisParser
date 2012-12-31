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
 * Template for .OM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Om extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant Contact ID)/is', 
            2 => '/Registrant Contact ID:(?>[\x20\t]*)(.*?)(?=Tech Contact ID)/is', 
            3 => '/Tech Contact ID:(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            4 => '/Name Server:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Last Modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^Registrant Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^Registrant Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Registrant Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Registrant Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            3 => array('/^Tech Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^Tech Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Tech Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^Tech Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country'), 
            4 => array('/^Name Server:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^Name Server IP:(?>[\x20\t]*)(.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Data Found/i';
}