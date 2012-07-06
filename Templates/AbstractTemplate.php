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
 * WhoisParser AbstractTemplate
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractTemplate
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array();

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array();

    /**
     * Writing data to properties
     *
     * @param  string $name
     * @param  mixed $value
     * @return void
     */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     *
     * @param  mixed $name
     * @return boolean
     */
    public function __isset($name)
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     *
     * @param  string $name
     * @return void
     */
    public function __get($name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }
        
        return null;
    }

    /**
     * Load Template
     * 
     * Returns a template object, if not null.
     *
     * @param  string $template
     * @return mixed
     */
    public static function factory($template)
    {
        if (file_exists(__DIR__ . '/' . ucfirst($template) . '.php')) {
            include_once __DIR__ . '/' . ucfirst($template) . '.php';
            $classname = 'Novutec\WhoisParser\Template_' . ucfirst($template);
            return new $classname();
        } else {
            return null;
        }
    }

    /**
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {}
}