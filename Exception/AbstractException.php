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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * AbstractException
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractException extends \Exception
{

    /**
     * Creates an exception object
     * 
     * @param  string $message
     * @param  integer $code
     * @param  Exception $previous
     * @return void
     */
    public function __construct($message = '', $code = 0, Exception $previous = null)
    {
        parent::__construct($message, (int) $code, $previous);
    }

    /**
     * Creates an exception object
     *
     * @param  string $type
     * @param  string $message
     * @param  integer $code
     * @param  Exception $previous
     * @return mixed
     */
    public static function factory($type = '', $message = '', $code = 0, Exception $previous = null)
    {
        if (file_exists(__DIR__ . '/' . ucfirst($type) . 'Exception.php')) {
            include_once __DIR__ . '/' . ucfirst($type) . 'Exception.php';
            $classname = 'Novutec\WhoisParser\\' . ucfirst($type) . 'Exception';
            return new $classname($message, $code, $previous);
        } else {
            include_once __DIR__ . '/Exception.php';
            $classname = 'Novutec\WhoisParser\Exception';
            return new $classname($message, $code, $previous);
        }
    }
}