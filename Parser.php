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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * @see Config/Config
 */
require_once 'Config/Config.php';

/**
 * @see Adapter/Adapter
 */
require_once 'Adapter/AbstractAdapter.php';

/**
 * @see Templates/Template
 */
require_once 'Templates/AbstractTemplate.php';

/**
 * @see Result/Result
 */
require_once 'Result/Result.php';

/**
 * @see Exception
 */
require_once 'Exception/AbstractException.php';

/**
 * WhoisParser
 * 
 * Automatically follows the WHOIS registry referral chains until it finds the
 * correct WHOIS for the most complete WHOIS data. Exceptionally robust WHOIS parser
 * that parses a variety of free form WHOIS data into well-structured data that your
 * application may read. Also returns an indication of whether a domain is available.
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Parser
{

    /**
     * WhoisParserConfig object
     * 
     * @var object
     * @access protected
     */
    protected $Config;

    /**
     * Query string sent to the WhoisParser
     * 
     * @var object
     * @access protected
     */
    protected $Query;

    /**
     * Raw output from whois server unformatted
     * 
     * @var string
     * @access protected
     */
    protected $rawdata;

    /**
     * WhoisParserResult object
     * 
     * @var object
     * @access protected
     */
    protected $Result;

    /**
     * Should the exceptions be thrown or caugth and trapped in the response?
     * 
     * @var boolean
     * @access protected
     */
    protected $throwExceptions = false;

    /**
     * Use cache for whois output?
     * 
     * @var boolean
     * @access protected
     */
    protected $useCache = false;

    /**
     * Contains special whois server like member whois configuration. It will be
     * used to overload the respective template in WhoisParserConfig.
     * 
     * @var array
     * @access protected
     */
    protected $specialWhois = array();

    /**
     * Output format 'object', 'array', 'json', 'serialize' or 'xml'
     *
     * @var string
     * @access protected
     */
    protected $format = 'object';

    /**
     * Output format for dates
     * 
     * @var string
     * @access protected
     */
    protected $dateformat = '%Y-%m-%d %H:%M:%S';

    /**
     * Activate cache
     * 
     * @var boolean
     * @access protected
     */
    protected $cache = true;

    /**
     * Creates a WhoisParser object
     * 
     * @param  string $format
	 * @return void
	 */
    public function __construct($format = 'object')
    {
        date_default_timezone_set('UTC');
        $this->setFormat($format);
    }

    /**
     * Set special whois server like member whois configuration. It will be
     * used to overload the respective template in WhoisParserConfig.
     * 
     * @param  array $specialWhois
	 * @return void
	 */
    public function setSpecialWhois($specialWhois)
    {
        $this->specialWhois = $specialWhois;
    }

    /**
	 * Lookup an IP address (ipv4 and ipv6) and domain names
	 * 
	 * @throws NoQueryException
	 * @throws instance of AbstractException if throwExceptions = true
	 * @param  string $query
	 * @return object
	 */
    public function lookup($query = '')
    {
        $this->Result = new Result();
        $this->Config = new Config($this->specialWhois);
        
        try {
            if ($query == '') {
                throw AbstractException::factory('NoQuery', 'No lookup query given.');
            }
            
            $this->prepare($query);
            
            if (isset($this->Query->ip)) {
                $config = $this->Config->get('iana');
            } else {
                if (isset($this->Query->tldGroup)) {
                    $config = $this->Config->get($this->Query->tldGroup, $this->Query->idnTld);
                } else {
                    $config = $this->Config->get($this->Query->asn);
                }
                
                if ($config['server'] == '' || $this->Query->domain == '') {
                    $config = $this->Config->get('iana');
                }
            }
            
            $this->Config->setCurrent($config);
            $this->call();
        } catch (AbstractException $e) {
            if ($this->throwExceptions) {
                throw $e;
            }
            
            $this->Result->addItem('exception', $e->getMessage());
            $this->Result->addItem('rawdata', explode("\n", $this->rawdata));
            
            if (isset($this->Query)) {
                
                if (isset($this->Query->ip)) {
                    $this->Result->addItem('name', $this->Query->ip);
                } else {
                    $this->Result->addItem('name', $this->Query->fqdn);
                }
            } else {
                $this->Result->addItem('name', $query);
            }
        }
        
        // call cleanUp method
        $this->Result->cleanUp($this->Config->getCurrent(), $this->dateformat);
        
        // peparing output of Result by format
        switch ($this->format) {
            case 'json':
                return $this->Result->toJson();
                break;
            case 'serialize':
                return $this->Result->serialize();
                break;
            case 'array':
                return $this->Result->toArray();
                break;
            case 'xml':
                return $this->Result->toXml();
                break;
            default:
                return $this->Result;
        }
    }

    /**
     * Parses the given query to get either the domain name or an IP address
     * 
     * @param  string $query
     * @return void
     */
    private function prepare($query)
    {
        // check if given query is an IP address and AS number or possible
        // domain name
        if ($this->bin2ip($this->ip2bin($query)) === $query) {
            $this->Query = new \stdClass();
            $this->Query->ip = $query;
        } elseif (preg_match('/^AS[0-9]*$/im', $query)) {
            $this->Query = new \stdClass();
            $this->Query->asn = $query;
        } else {
            $Parser = new \Novutec\DomainParser\Parser();
            $this->Query = $Parser->parse(filter_var($query, FILTER_SANITIZE_STRING));
        }
    }

    /**
     * Send data to whois server and call parse() to process rawdata
     * 
     * @throws NoAdapterException
     * @param  object $query
	 * @return void
	 */
    public function call($query = '')
    {
        if ($query != '') {
            $this->Query = filter_var($query, FILTER_SANITIZE_STRING);
        }
        
        $Config = $this->Config->getCurrent();
        $Adapter = AbstractAdapter::factory($Config['adapter']);
        
        if ($Adapter instanceof AbstractAdapter) {
            $this->rawdata = strip_tags($Adapter->call($this->Query, $Config));
            $this->parse();
        } else {
            throw AbstractException::factory('NoAdapter', 'Adapter ' . $Config['adapter'] .
                     ' could not be found.');
        }
    }

    /**
     * Parses rawdata from whois server and call postProcess if exists afterwards
     * 
     * @throws NoTemplateException
     * @return void
     */
    private function parse()
    {
        $Config = $this->Config->getCurrent();
        
        $Template = AbstractTemplate::factory($Config['template']);
        
        // If Template is null then we do not have a template for that, but we
        // can still proceed to the end with just the rawdata
        if ($Template instanceof AbstractTemplate) {
            $this->parseTemplate($Template);
            
            // set rawdata to Result - this happens here because sometimes we
            // have to fix the rawdata as well in postProcess
            $this->Result->addItem('rawdata', explode("\n", $this->rawdata));
            
            // check availability upon type - IP addresses are always registered
            if (isset($Template->available) && $Template->available != '') {
                preg_match_all($Template->available, $this->rawdata, $matches);
                
                $this->Result->addItem('registered', empty($matches[0]));
            }
            
            // set registered to Result
            $this->Result->addItem('registered', isset($this->Result->registered) ? $this->Result->registered : false);
            
            if (! isset($this->Result->whoisserver)) {
                $this->Result->addItem('whoisserver', $Config['server']);
            }
            
            // start post processing
            $Template->postProcess($this);
            
            // set name to Result
            if (isset($this->Query->tld) && ! isset($this->Query->fqdn)) {
                $this->Result->addItem('name', $this->Query->tld);
            } elseif (isset($this->Query->ip)) {
                $this->Result->addItem('name', $this->Query->ip);
            } elseif (isset($this->Query->asn)) {
                $this->Result->addItem('name', $this->Query->asn);
            } else {
                $this->Result->addItem('name', $this->Query->fqdn);
                $this->Result->addItem('idnName', $this->Query->idnFqdn);
            }
        } else {
            throw AbstractException::factory('NoTemplate', 'Template ' . $Config['template'] .
                     ' could not be found.');
        }
    }

    /**
     * Converts IP address to binary
     * 
     * @param  string $ip
     * @return mixed
     */
    private function ip2bin($ip)
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return base_convert(ip2long($ip), 10, 2);
        }
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return false;
        }
        
        if (($ip_n = inet_pton($ip)) === false) {
            return false;
        }
        
        $bits = 15; // 16 x 8 bit = 128bit (ipv6)
        $ipbin = '';
        
        while ($bits >= 0) {
            $bin = sprintf('%08b', (ord($ip_n[$bits])));
            $ipbin = $bin . $ipbin;
            $bits = $bits - 1;
        }
        
        return $ipbin;
    }

    /**
     * Converts binary to IP address
     * 
     * @param  string $bin
     * @return mixed
     */
    private function bin2ip($bin)
    {
        if (strlen($bin) <= 32) {
            // 32bits (ipv4)
            return long2ip(base_convert($bin, 2, 10));
        }
        
        if (strlen($bin) !== 128) {
            return false;
        }
        
        $pad = 128 - strlen($bin);
        
        for ($i = 1; $i <= $pad; $i++) {
            $bin = '0' . $bin;
        }
        
        $bits = 0;
        $ipv6 = '';
        
        while ($bits <= 7) {
            $bin_part = substr($bin, ($bits * 16), 16);
            $ipv6 = $ipv6 . dechex(bindec($bin_part)) . ':';
            $bits = $bits + 1;
        }
        
        return inet_ntop(inet_pton(substr($ipv6, 0, - 1)));
    }

    /**
     * Parses rawdata by Template
     * 
     * @param  object $Template
     * @param  string $rawdata
     * @return void
     */
    private function parseTemplate($Template)
    {
        // check if there is a block to be cutted from HTML response
        if (isset($Template->htmlBlock)) {
            preg_match($Template->htmlBlock, $this->rawdata, $htmlMatches);
            
            if (isset($htmlMatches[0])) {
                $this->rawdata = preg_replace('/\s\s+/', "\n", $htmlMatches[0]);
            }
        }
        
        // lookup all blocks of template
        foreach ($Template->blocks as $blockKey => $blockRegEx) {
            // try to match block regex against WHOIS rawdata
            if (preg_match_all($blockRegEx, $this->rawdata, $blockMatches)) {
                // use matched block to lookup for blockItems
                foreach ($blockMatches[0] as $item) {
                    foreach ($Template->blockItems[$blockKey] as $itemRegEx => $target) {
                        // try to match blockItem regex against block
                        if (preg_match_all($itemRegEx, $item, $itemMatches)) {
                            // set matched items to Result
                            $this->Result->addItem($target, end($itemMatches));
                        }
                    }
                }
            }
        }
        
        // if there are still contact handles after parsing then
        // these contacts are used for more types e.g. one handle for admin and
        // tech so we are going to clone this matching handles
        if (isset($this->Result->network->contacts)) {
            // lookup all left over handles in network
            foreach ($this->Result->network->contacts as $type => $handle) {
                if (is_string($handle)) {
                    // lookup all contacts in Result
                    foreach ($this->Result->contacts as $contactType => $contactArray) {
                        foreach ($contactArray as $contactObject) {
                            // if contact handle in network matches the one in
                            // Result, we have to clone it
                            if (strtolower($contactObject->handle) === strtolower($handle)) {
                                if (empty($this->Result->contacts->$type)) {
                                    $this->Result->contacts->$type = Array();
                                }
                                array_push($this->Result->contacts->$type, $contactObject);
                                unset($this->Result->network->contacts->$type);
                                break 2;
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Returns WhoisParserResult instance
     * 
     * @return object
     */
    public function getResult()
    {
        return $this->Result;
    }

    /**
     * Returns WhoisParserConfig instance
     * 
     * @return object
     */
    public function getConfig()
    {
        return $this->Config;
    }

    /**
     * Returns WhoisParser Query
     *
     * @return object
     */
    public function getQuery()
    {
        return $this->Query;
    }

    /**
     * Set output format
     *
     * You may choose between 'object', 'array', 'json', 'serialize' or 'xml' output format
     *
     * @param  string $format
     * @return void
     */
    public function setFormat($format = 'object')
    {
        $this->format = filter_var($format, FILTER_SANITIZE_STRING);
    }

    /**
     * Set date format
     * 
     * You may choose your own date format. Please check http://php.net/strftime for further
     * details
     * 
     * @param  string $dateformat
     * @return void
     */
    public function setDateFormat($dateformat = '%Y-%m-%d %H:%M:%S')
    {
        $this->dateformat = $dateformat;
    }

    /**
     * Set the cache flag
     *
     * If cache flag is set, the WHOIS parser will cache the query and rawdata.
     *
     * @param  boolean $cache
     * @return void
     */
    public function useCache($cache = true)
    {
        $this->cache = filter_var($cache, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Set the throwExceptions flag
     *
     * Set whether exceptions encounted in the dispatch loop should be thrown
     * or caught and trapped in the response object.
     *
     * Default behaviour is to trap them in the response object; call this
     * method to have them thrown.
     *
     * @param  boolean $throwExceptions
     * @return void
     */
    public function throwExceptions($throwExceptions = false)
    {
        $this->throwExceptions = filter_var($throwExceptions, FILTER_VALIDATE_BOOLEAN);
    }
}
