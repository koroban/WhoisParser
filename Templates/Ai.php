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
 * Template for .AI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ai extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Organization Using Domain Name(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            2 => '/Administrative Contact(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            4 => '/Billing Contact(?>[\x20\t]*)(.*?)(?=Nameservers)/is', 
            5 => '/Nameservers(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/Organization Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Street Address(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/State(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:state', 
                    '/Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:zipcode', 
                    '/Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:country'), 
            2 => array(
                    '/NIC Handle \(if known\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/\(I\)ndividual \(R\)ole(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:type', 
                    '/Name \(Last, First\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Organization Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Street Address(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/State(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:state', 
                    '/Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:zipcode', 
                    '/Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:country', 
                    '/Phone Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:phone', 
                    '/Fax Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:fax', 
                    '/E-Mailbox(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:email'), 
            3 => array(
                    '/NIC Handle \(if known\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/\(I\)ndividual \(R\)ole(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:type', 
                    '/Name \(Last, First\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Organization Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Street Address(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/State(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:state', 
                    '/Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:zipcode', 
                    '/Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:country', 
                    '/Phone Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:phone', 
                    '/Fax Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:fax', 
                    '/E-Mailbox(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:email'), 
            4 => array(
                    '/NIC Handle \(if known\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/\(I\)ndividual \(R\)ole(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:type', 
                    '/Name \(Last, First\)(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/Organization Name(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/Street Address(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/City(?>[\.]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/State(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:state', 
                    '/Postal Code(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:zipcode', 
                    '/Country(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:country', 
                    '/Phone Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:phone', 
                    '/Fax Number(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:fax', 
                    '/E-Mailbox(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:billing:email'), 
            5 => array('/Server Hostname(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'nameserver', 
                    '/Server Netaddress(?>[\.]*):(?>[\x20\t]*)(.*)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/If you would like to register this/i';
}