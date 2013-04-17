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
 * Template for Neustar (.BIZ, .CO, .US, .TRAVEL)
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Neustar extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant id\:)/is', 
            2 => '/registrant id:(?>[\x20\t]*)(.*?)(?=administrative contact id\:)/is', 
            3 => '/administrative contact id:(?>[\x20\t]*)(.*?)(?=billing contact id\:)/is', 
            4 => '/billing contact id:(?>[\x20\t]*)(.*?)(?=technical contact id\:)/is', 
            5 => '/technical contact id:(?>[\x20\t]*)(.*?)(?=name server\:)/is', 
            6 => '/name server:(?>[\x20\t]*)(.*?)(?=created by registrar\:)/is', 
            7 => '/domain registration date:(?>[\x20\t]*)(.*?)(?=>>>>)/is');

    /**
	 * items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/sponsoring registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/sponsoring registrar iana id:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/registrar url \(registration services\):(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/(?>domain )*status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/registrant id:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/registrant name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/registrant organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/registrant address[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:owner:address', 
                    '/registrant city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/registrant state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/registrant postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/registrant country code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/registrant phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/registrant facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/registrant email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/registrant application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:application_purpose', 
                    '/registrant nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:nexus_category'), 
            3 => array(
                    '/administrative contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/administrative contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/administrative contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/administrative contact address[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:admin:address', 
                    '/administrative contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/administrative contact state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/administrative contact postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/administrative contact country code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/administrative contact phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/administrative contact facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/administrative contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/administrative application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:application_purpose', 
                    '/administrative nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:nexus_category'), 
            4 => array('/billing contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/billing contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/billing contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/billing contact address[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:billing:address', 
                    '/billing contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/billing contact state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/billing contact postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/billing contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/billing contact phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/billing contact facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/billing contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/billing application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:application_purpose', 
                    '/billing nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:nexus_category'), 
            5 => array('/technical contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/technical contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/technical contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/technical contact (street|address)[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:tech:address', 
                    '/technical contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/technical contact state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/technical contact postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/technical contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/technical contact phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/technical contact facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/technical contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/technical application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:application_purpose', 
                    '/technical nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:nexus_category'), 
            6 => array('/name server:(?>[\x20\t]+)(.+)$/im' => 'nameserver'), 
            7 => array('/domain registration date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/domain expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/domain last updated date:(?>[\x20\t]*)(.+)$/im' => 'changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not found:/i';
}