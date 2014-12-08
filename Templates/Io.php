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
 * Template for ICB .AC, .SH, .IO and .TM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Io extends Regex
{
    protected $convertFromHtml = true;

    /**
     * Cut block from HTML output for $blocks
     *
     * @var string
     * @access protected
     */
    protected $htmlBlock = '/<!--- ### --->(.*?)<!--- ### --->/is';

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(1 => '/Domain Information(.*?)(?=Domain Owner)/is',
        2 => '/Domain Owner(.*?)(?=Admin Contact)/is',
        3 => '/Admin Contact(.*?)(?=Technical Contact)/is',
        4 => '/Technical Contact(.*?)(?=Billing Contact)/is',
        5 => '/Billing Contact(.*?)(?=Registrar)/is',
        6 => '/Registrar\s*User ID(.*?)(?=Primary Nameserver)/is',
        7 => '/Primary Nameserver(.*?)$/is');

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array('/Organization Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:organization',
            '/Street\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:address',
            '/City\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:city',
            '/State\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:state',
            '/Postal Code\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:zipcode',
            '/Country\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:country',
            '/First Registered\s*:(?>[\x20\t]*)(.+)/i' => 'created',
            '/Last Updated\s*:(?>[\x20\t]*)(.+)/i' => 'changed',
            '/Expires\s*:(?>[\x20\t]*)(.+)/i' => 'expires',
            '/Domain Status\s*:(?>[\x20\t]*)(.+)/i' => 'status',
        ),
        2 => array('/User ID\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:handle',
            '/Contact Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:name',
            '/Organization Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:organization',
            '/Street\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:address',
            '/City\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:city',
            '/State\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:state',
            '/Postal Code\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:zipcode',
            '/Country\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:country',
            '/Phone\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:phone',
            '/Fax\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:fax',
            '/E-Mail\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:owner:email'),
        3 => array('/User ID\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:handle',
            '/Contact Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:name',
            '/Organization Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:organization',
            '/Street\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:address',
            '/City\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:city',
            '/State\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:state',
            '/Postal Code\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:zipcode',
            '/Country\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:country',
            '/Phone\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:phone',
            '/Fax\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:fax',
            '/E-Mail\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:admin:email'),
        4 => array('/User ID\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:handle',
            '/Contact Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:name',
            '/Organization Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:organization',
            '/Street\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:address',
            '/City\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:city',
            '/State\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:state',
            '/Postal Code\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:zipcode',
            '/Country\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:country',
            '/Phone\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:phone',
            '/Fax\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:fax',
            '/E-Mail\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:tech:email'),
        5 => array('/User ID\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:handle',
            '/Contact Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:name',
            '/Organization Name\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:organization',
            '/Street\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:address',
            '/City\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:city',
            '/State\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:state',
            '/Postal Code\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:zipcode',
            '/Country\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:country',
            '/Phone\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:phone',
            '/Fax\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:fax',
            '/E-Mail\s*:(?>[\x20\t]*)(.+)/i' => 'contacts:billing:email'),
        6 => array('/User ID\s*:(?>[\x20\t]*)(.+)/i' => 'registrar:id',
            '/Organization Name\s*:(?>[\x20\t]*)(.+)/i' => 'registrar:name',
            '/Phone\s*:(?>[\x20\t]*)(.+)/i' => 'registrar:phone',
            '/Fax\s*:(?>[\x20\t]*)(.+)/i' => 'registrar:fax',
            '/E-Mail\s*:(?>[\x20\t]*)(.+)/i' => 'registrar:email'),
        7 => array('/Name Server\s*:(?>[\x20\t]*)(.+)/i' => 'nameserver',
            '/IP Address\s*:(?>[\x20\t]*)(.+)/i' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(There is no live registration)/i';


    public function translateRawData($rawdata, $config)
    {
        return strip_tags($rawdata);
    }
}
