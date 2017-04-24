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
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for IANA #625
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Email extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
            1 => '/Domain Name(?>[\x20\t]*)(.*?)(?=Registrant Name)/is', 
            2 => '/Registrant Name(?>[\x20\t]*)(.*?)(?=Admin Name)/is', 
            3 => '/Admin Name(?>[\x20\t]*)(.*?)(?=Tech Name)/is', 
            4 => '/Tech Name(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            5 => '/Name Server(?>[\x20\t]*)(.*?)$/is',
    );

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
            1 => array(
                    // Registrar Details
                    '/Registry Registrant ID(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/Registrar(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Abuse Contact Email(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/Registrar Abuse Contact Phone(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:phone', 
                    '/Registrar URL(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 

                    // Registration Details
                    '/^creation date:(.+)$/im' => 'created',
                    '/^updated date:(.+)$/im' => 'changed',
                    '/^registry expiry date:(.+)$/im' => 'expires',
                    '/^domain status:(.+)$/im' => 'registered',
            ),
            2 => array(
                    // Owner details
                    '/Registrant Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Registrant Organization(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Registrant Street(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/Registrant City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/Registrant State\/Province(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:state', 
                    '/Registrant Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:zipcode', 
                    '/Registrant Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:country',
                    '/Registrant Phone(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:phone',
                    '/Registrant Fax(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:fax',
                    '/Registrant Email(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:email',
            ),
            3 => array(
                    // Admin details
                    '/Admin Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Admin Organization(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Admin Street(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/Admin City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/Admin State\/Province(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:state', 
                    '/Admin Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:zipcode', 
                    '/Admin Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:country',
                    '/Admin Phone(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:phone',
                    '/Admin Fax(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:fax',
                    '/Admin Email(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:email',
            ),
            4 => array(
                    // Tech details
                    '/Tech Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Tech Organization(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Tech Street(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/Tech City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/Tech State\/Province(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:state', 
                    '/Tech Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:zipcode', 
                    '/Tech Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:country',
                    '/Tech Phone(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:phone',
                    '/Tech Fax(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:fax',
                    '/Tech Email(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:email',
            ),
            5 => array(
                    // Name servers
                    '/Name Server(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'nameserver',
            )
    );
}