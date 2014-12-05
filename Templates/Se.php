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
 * Template for .SE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 * @author     estshy <estshy.pl>
 */
class Template_Se extends AbstractTemplate
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/state(.*?)$/is',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/^nserver:(?>[\s]+)(.+)$/im'       => 'nameserver',
            '/^created:(?>[\x20\t]*)(.+)$/im'   => 'created',
            '/^modified:(?>[\x20\t]*)(.+)$/im'  => 'changed',
            '/^expires:(?>[\x20\t]*)(.+)$/im'   => 'expires',
            '/^registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
        ),
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/" not found./i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        if ($ResultSet->dnssec === 'Unsigned') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}
