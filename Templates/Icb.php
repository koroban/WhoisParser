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
 * Template for ICB .AC, .SH, .IO and .TM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Icb extends AbstractTemplate
{

    /**
     * Cut block from HTML output for $blocks
     * 
     * @var string
     * @access protected
     */
    protected $htmlBlock = '/Domain Information(.*?)are issued on a first come/is';

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Information(.*?)(?=Admin Contact)/is', 
            2 => '/Admin Contact(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact(.*?)(?=Billing Contact)/is', 
            4 => '/Primary Nameserver(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Organization Name : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:organization',
                    '/Street : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:address',
                    '/City : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:city',
                    '/State : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:state',
                    '/Postal Code : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:zipcode',
                    '/Country : (?>[\x20\t]*)(.+)/i' => 'contacts:owner:country',
                    '/First Registered : (?>[\x20\t]*)(.+)/i' => 'created',
                    '/Last Updated : (?>[\x20\t]*)(.+)/i' => 'changed',
                    '/Domain Status : (?>[\x20\t]*)(.+)/i' => 'status',
                    '/Expires : (?>[\x20\t]*)(.+)/i' => 'expires'),
            2 => array('/User ID : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:handle',
                    '/Contact Name : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:name',
                    '/Organization Name : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:organization',
                    '/Street : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:address',
                    '/City : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:city',
                    '/State : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:state',
                    '/Postal Code : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:zipcode',
                    '/Country : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:country',
                    '/Phone : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:phone',
                    '/Fax : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:fax',
                    '/E-Mail : (?>[\x20\t]*)(.+)/i' => 'contacts:admin:email'),
            3 => array('/User ID : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:handle',
                    '/Contact Name : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:name',
                    '/Organization Name : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:organization',
                    '/Street : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:address',
                    '/City : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:city',
                    '/State : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:state',
                    '/Postal Code : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:zipcode',
                    '/Country : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:country',
                    '/Phone : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:phone',
                    '/Fax : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:fax',
                    '/E-Mail : (?>[\x20\t]*)(.+)/i' => 'contacts:tech:email'),
            4 => array('/Name Server : (?>[\x20\t]*)(.+)/i' => 'nameserver',
                    '/IP Address : (?>[\x20\t]*)(.+)/i' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/available for purchase/i';
}