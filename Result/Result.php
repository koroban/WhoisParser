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
 * @namespace Novutec\WhoisParser\Result
 */
namespace Novutec\WhoisParser\Result;

/**
 * WhoisParser Result
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Result extends AbstractResult
{

    /**
     * Name of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $name;

    /**
     * IDN converted name of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $idnName;

    /**
     * Status of domain or IP address
     *
     * @var array
     * @access protected
     */
    protected $status;

    /**
     * Array of Nameservers
     *
     * @var array
     * @access protected
     */
    protected $nameserver;

    /**
     * Array of Nameservers IPs
     *
     * @var array
     * @access protected
     */
    protected $ips;

    /**
     * Created date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $created;

    /**
     * Last changed date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $changed;

    /**
     * Expire date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $expires;

    /**
     * Is domain name or IP address registered
     *
     * @var boolean
     * @access protected
     */
    protected $registered;

    /**
     * Has domain name DNSSEC
     *
     * @var boolean
     * @access protected
     */
    protected $dnssec;

    /**
     * Queried whois server
     *
     * @var string
     * @access protected
     */
    protected $whoisserver;

    /**
     * Contact handles of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $contacts;

    /**
     * Registrar of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $registrar;

    /**
     * Raw response from whois server
     *
     * @var array
     * @access protected
     */
    public $rawdata = array();

    /**
     * Network information of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $network;

    /**
     * Exception
     *
     * @var string
     * @access protected
     */
    protected $exception;

    /**
     * Have contacts been parsed?
     * 
     * @var boolean
     * @access protected
     */
    protected $parsedContacts;

    /**
     * Name of the actual template
     *
     * @var string
     * @access protected
     */
    public $template;

    /**
	 * Creates a WhoisParserResult object
	 *
	 * @return void
	 */
    public function __construct()
    {
        $this->contacts = new \stdClass();
        $this->lastId = - 1;
    }

    /**
     * @param  string $target
     * @param  mixed $value
     * @param bool $append Append values rather than overwriting? (Ignored for registrars and contacts)
     * @return void
     */
    public function addItem($target, $value, $append = false)
    {
        if (is_array($value) && sizeof($value) === 1) {
            $value = $value[0];
        }
        // Don't overwrite existing values with empty values, unless we explicitly pass through NULL
        if (is_array($value) && (sizeof($value) === 0)) {
            return;
        }
        if (is_string($value) && (strlen($value) < 1) && ($value !== NULL)) {
            return;
        }

        // reservedType is sometimes need by templates like .DE
        if ($target === 'contacts:reservedType') {
            if ($this->lastHandle !== strtolower($value)) {
                $this->lastId = - 1;
            }
            
            $this->lastHandle = strtolower($value);
            $this->lastId++;
            return;
        }

        if ($target == 'rawdata') {
            $this->{$target}[] = $value;
            return;
        }

        if (strpos($target, ':')) {
            // split target by :
            $targetArray = explode(':', $target);
            $element = &$this;
            
            // lookup target to determine where we should add the item
            foreach ($targetArray as $key => $type) {
                if ($targetArray[0] === 'contacts' && $key === 1 && sizeof($targetArray) === 2) {
                    // estimate handle match by network contacts
                    if (isset($this->network->contacts) && $targetArray[1] === 'handle') {
                        // look through all network contacts
                        foreach ($this->network->contacts as $networkContactKey => $networkContactValue) {
                            // if it is an array, then there are more contacts
                            // of the same type
                            if (is_array($networkContactValue)) {
                                // look through the array of one type
                                foreach ($networkContactValue as $multiContactKey => $multiContactValue) {
                                    if (strtolower($multiContactValue) === strtolower($value)) {
                                        if ($this->lastHandle !== $networkContactKey) {
                                            $this->lastId = - 1;
                                        }
                                        
                                        $this->lastHandle = $networkContactKey;
                                        $this->lastId++;
                                        unset($this->network->contacts->{$networkContactKey}[$multiContactKey]);
                                        break 2;
                                    }
                                }
                            } else {
                                if (strtolower($networkContactValue) === strtolower($value)) {
                                    if ($this->lastHandle !== $networkContactKey) {
                                        $this->lastId = - 1;
                                    }
                                    $this->lastHandle = $networkContactKey;
                                    $this->lastId++;
                                    unset($this->network->contacts->$networkContactKey);
                                    break;
                                }
                            }
                        }
                    }
                    
                    if (! isset($this->contacts->{$this->lastHandle}[$this->lastId])) {
                        // This happens if the template fails to parse contacts correctly
                        // But normally causes a fatal error, so unless we manually trigger an error first,
                        // all stacktrace information is lost
                        if (($this->lastId === -1) || ($this->lastHandle === null)) {
                            trigger_error("Unexpected values for lastHandle / lastId", E_USER_WARNING);
                        }
                        $this->contacts->{$this->lastHandle}[$this->lastId] = new Contact();
                    }

                    $contact = $this->contacts->{$this->lastHandle}[$this->lastId];
                    $contact->addItem($type, $value, $append);
                } else {
                    // if last element of target is reached we need to add value
                    if ($key === sizeof($targetArray) - 1) {
                        $targetItem = $element;
                        if (is_array($targetItem)) {
                            $targetItem = $targetItem[sizeof($targetItem) - 1];
                        }
                        $targetItem->addItem($type, $value, $append);
                        break;
                    }
                    
                    if (! isset($element->$type)) {
                        switch ($targetArray[0]) {
                            case 'contacts':
                                if (empty($element->$type)) {
                                    $element->$type = array();
                                }
                                
                                array_push($element->$type, new Contact());
                                break;
                            case 'registrar':
                                $element->$type = new Registrar();
                                break;
                            default:
                                $element->$type = new OtherResult();
                        }
                    }
                    
                    $element = &$element->$type;
                }
            }
        } else {
            if ($append && isset($this->{$target})) {
                if (!is_array($this->{$target})) {
                    $this->{$target} = array($this->{$target});
                }
                $this->{$target}[] = $value;
            } else {
                $this->{$target} = $value;
            }
        }
    }

    /**
     * Resets the result properties to empty
     *  
     * @return void
     */
    public function reset()
    {
        foreach ($this as $key => $value) {
            $this->$key = null;
        }
        
        // need to set contacts to stdClass otherwise it will not working to
        // add items again
        $this->contacts = new \stdClass();
        $this->lastId = - 1;
    }


    /**
     * Convert properties to array
     * 
     * @return array
     */
    public function toArray()
    {
        $output = get_object_vars($this);
        $contacts = array();
        $network = array();
        
        // lookup all contact handles and convert to array
        foreach ($this->contacts as $type => $handle) {
            foreach ($handle as $number => $object) {
                $contacts[$type][$number] = $object->toArray();
            }
        }
        $output['contacts'] = $contacts;
        
        if (! empty($this->registrar)) {
            $output['registrar'] = $this->registrar->toArray();
        }
        
        if (! empty($this->network)) {
            // lookup network for all properties
            foreach ($this->network as $type => $value) {
                // if there is an object we need to convert it to array
                if (is_object($value)) {
                    $value = (array) $value;
                    // if converted array is empty there is no need to add it
                    if (! empty($value)) {
                        $network[$type] = $value;
                    }
                } else {
                    $network[$type] = $value;
                }
            }
            $output['network'] = $network;
        }
        
        return $output;
    }

    /**
     * Serialize properties
     *
     * @return string
     */
    public function serialize()
    {
        return serialize($this->toArray());
    }

    /**
     * Convert properties to xml by using SimpleXMLElement
     *
     * @return string
     */
    public function toXml()
    {
        $xml = new \SimpleXMLElement(
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><whois></whois>');
        
        $output = get_object_vars($this);
        
        // lookup all object variables
        foreach ($output as $name => $var) {
            // if variable is an array add it to xml
            if (is_array($var)) {
                $child = $xml->addChild($name);
                
                foreach ($var as $firstKey => $firstValue) {
                    $child->addChild('item', trim(htmlspecialchars($firstValue)));
                }
            } elseif (is_object($var)) {
                // if variable is an object we need to convert it to array
                $child = $xml->addChild($name);
                
                // if it is not a stdClass object we have the toArray() method
                if (! $var instanceof \stdClass) {
                    $firstArray = $var->toArray();
                    
                    foreach ($firstArray as $firstKey => $firstValue) {
                        if (! is_array($firstValue)) {
                            $child->addChild($firstKey, trim(htmlspecialchars($firstValue)));
                        } else {
                            $secondChild = $child->addChild($firstKey);
                            
                            foreach ($firstValue as $secondKey => $secondString) {
                                $secondChild->addChild('item', trim(htmlspecialchars($secondString)));
                            }
                        }
                    }
                } else {
                    // if it is an stdClass object we need to convert it
                    // manually
                    
                    // lookup all properties of stdClass and convert it
                    foreach ($var as $firstKey => $firstValue) {
                        if (! $firstValue instanceof \stdClass && ! is_array($firstValue) &&
                                 ! is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey);
                            
                            $firstArray = $firstValue->toArray();
                            
                            foreach ($firstArray as $secondKey => $secondValue) {
                                $secondChild->addChild($secondKey, trim(htmlspecialchars($secondValue)));
                            }
                        } elseif (is_array($firstValue)) {
                            $secondChild = $child->addChild($firstKey);
                            
                            foreach ($firstValue as $secondKey => $secondValue) {
                                $secondArray = $secondValue->toArray();
                                $thirdChild = $secondChild->addChild('item');
                                
                                foreach ($secondArray as $thirdKey => $thirdValue) {
                                    if (! is_array($thirdValue)) {
                                        $thirdChild->addChild($thirdKey, trim(htmlspecialchars($thirdValue)));
                                    } else {
                                        $fourthChild = $thirdChild->addChild($thirdKey);
                                        
                                        foreach ($thirdValue as $fourthKey => $fourthValue) {
                                            $fourthChild->addChild('item', trim(htmlspecialchars($fourthValue)));
                                        }
                                    }
                                }
                            }
                        } elseif (is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey, $firstValue);
                        }
                    }
                }
            } else {
                $xml->addChild($name, trim($var));
            }
        }
        
        return $xml->asXML();
    }

    /**
     * cleanUp method will be called before output
     * 
     * @return void
     */
    public function cleanUp($config, $dateformat)
    {
        // add WHOIS server to output
        $this->addItem('whoisserver', ($config['adapter'] === 'http') ? $config['server'] .
                 str_replace('%domain%', $this->name, $config['format']) : $config['server']);
        
        // remove helper vars from result
        if (isset($this->lastId)) {
            unset($this->lastId);
        }
        
        if (isset($this->lastHandle)) {
            unset($this->lastHandle);
        }
        
        // format dates
        $this->template[$this->whoisserver] = $config['template'];
        $this->changed = $this->formatDate($dateformat, $this->changed);
        $this->created = $this->formatDate($dateformat, $this->created);
        $this->expires = $this->formatDate($dateformat, $this->expires);
        
        foreach ($this->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->created = $this->formatDate($dateformat, $contactObject->created);
                $contactObject->changed = $this->formatDate($dateformat, $contactObject->changed);
            }
        }
        
        // check if contacts have been parsed
        if (sizeof(get_object_vars($this->contacts)) > 0) {
            $this->addItem('parsedContacts', true);
        } else {
            $this->addItem('parsedContacts', false);
        }
    }

    /**
     * Format given dates by date format
     *
     * @param  string $dateformat
     * @param  string $date
     * @return string
     */
    private function formatDate($dateformat, $date)
    {
        if (!is_string($date)) {
            return null;
        }
        $timestamp = strtotime(str_replace('/', '-', $date));

        if ($timestamp == '') {
            $timestamp = strtotime(str_replace('/', '.', $date));
        }

        return (strlen($timestamp) ? strftime($dateformat, $timestamp) : $date);
    }


    /**
     * Merge another result with this one, taking the other results values as preferred.
     *
     * @param Result $result
     * @todo Do we want to improve handling of contacts? How to handle multiple contacts of same type?
     */
    public function mergeFrom(Result $result)
    {
        $properties = array_keys(get_object_vars($result));
        foreach ($properties as $prop) {
            // Foreign value not set
            if ($result->$prop === null) {
                continue;
            }

            // Foreign value is an empty array
            if (is_array($result->$prop) && (count($result->$prop) < 1)) {
                continue;
            }

            // Foreign value is an empty string
            if (is_string($result->$prop) && (strlen($result->$prop) < 1)) {
                continue;
            }

            $this->$prop = $result->$prop;
        }
    }
}