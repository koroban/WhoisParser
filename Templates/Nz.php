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
 * Template for .NZ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Nz extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain_name:(?>[\x20\t]*)(.*?)(?=registrar_name)/is', 
            2 => '/registrar_name:(?>[\x20\t]*)(.*?)(?=registrant_contact_name)/is', 
            3 => '/registrant_contact_name:(?>[\x20\t]*)(.*?)(?=admin_contact_name)/is', 
            4 => '/admin_contact_name:(?>[\x20\t]*)(.*?)(?=technical_contact_name)/is', 
            5 => '/technical_contact_name:(?>[\x20\t]*)(.*?)(?=ns_name_01)/is', 
            6 => '/ns_name_01:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^query_status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^domain_dateregistered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^domain_datebilleduntil:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^domain_datelastmodified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^domain_signed:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            2 => array('/^registrar_name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^registrar_email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            3 => array(
                    '/^registrant_contact_name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^registrant_contact_address[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^registrant_contact_city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^registrant_contact_province:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^registrant_contact_postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^registrant_contact_country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^registrant_contact_phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^registrant_contact_fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^registrant_contact_email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'), 
            4 => array(
                    '/^admin_contact_name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^admin_contact_address[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^admin_contact_city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^admin_contact_province:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^admin_contact_postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^admin_contact_country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^admin_contact_phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^admin_contact_fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^admin_contact_email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            5 => array(
                    '/^technical_contact_name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^technical_contact_address[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^technical_contact_city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^technical_contact_province:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^technical_contact_postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^technical_contact_country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^technical_contact_phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^technical_contact_fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^technical_contact_email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            6 => array('/^ns_name_0[0-9]:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/query_status: 220 Available/i';

    /**
     * After parsing ...
     *
     * If dnssec was matched before it we switch dnssec to true otherwise to false
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != 'no') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}