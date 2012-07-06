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
 * Template for Gtld_schlund
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_schlund extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=nserver)/is', 
            2 => '/nserver:(?>[\x20\t]*)(.*?)(?=status)/is', 
            3 => '/registrant-firstname:(?>[\x20\t]*)(.*?)(?=admin-c-firstname)/is', 
            4 => '/admin-c-firstname:(?>[\x20\t]*)(.*?)(?=tech-c-firstname)/is', 
            5 => '/tech-c-firstname:(?>[\x20\t]*)(.*?)(?=bill-c-firstname)/is', 
            6 => '/bill-c-firstname:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^last-changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^registration-expiration:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            3 => array(
                    '/^registrant-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^registrant-(first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^registrant-street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^registrant-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^registrant-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^registrant-pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^registrant-ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^registrant-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^registrant-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^registrant-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            4 => array(
                    '/^admin-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^admin-c-(first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^admin-c-street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^admin-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^admin-c-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^admin-c-pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^admin-c-ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^admin-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^admin-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^admin-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            5 => array(
                    '/^tech-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^tech-c-(first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tech-c-street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tech-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tech-c-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^tech-c-pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tech-c-ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tech-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^tech-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^tech-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            6 => array(
                    '/^bill-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^bill-c-(first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^bill-c-street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^bill-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^bill-c-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/^bill-c-pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^bill-c-ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^bill-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^bill-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^bill-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'));
}