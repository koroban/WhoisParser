<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Enetica extends Regex
{
    protected $blocks = array(
        1 => '/^\s*Registrant Details:(.*?)\n\n/ims',
        3 => '/^\s*Domain Name:[^\n]+\n\n(.*?)\n\n/ims',
        4 => '/Administrative(_| )contact(.*?)\n\n/ims',
        5 => '/Billing(_| )contact(.*?)\n\n/ims',
        6 => '/Technical(_| )contact(.*?)\n\n/ims',
        7 => '/Zone(_| )contact(.*?)\n\n/ims',
        8 => '/^\s*Name Server:(.*?)The information/ims',
    );


    protected $blockItems = array(
        1 => array(
            '/^\s*Registrant:(.*)/ims' => 'contacts:owner:address',
        ),
        3 => array(
            '/^\s*Domain Name:(.*)/im' => 'name',
            '/^\s*Created on\.*:(.*)/im' => 'created',
            '/^\s*Expires on\.*:(.*)/im' => 'expires',
            '/^\s*Record last updated on\.*:(.*)/im' => 'changed',
        ),
        4 => array(
            '/contact:\n(.*)/ims' => 'contacts:admin:address',
        ),
        5 => array(
            '/contact:\n(.*)/ims' => 'contacts:billing:address',
        ),
        6 => array(
            '/contact:\n(.*)/ims' => 'contacts:tech:address',
        ),
        7 => array(
            '/contact:\n(.*)/ims' => 'contacts:zone:address',
        ),
        8 => array(
            '/^\sName Server:(.*)$/im' => 'nameserver',
            '/^\sRegistrar of Record:(.*)$/im' => 'registrar:name',
            '/^\sRecord last updated on (.*)$/im' => 'changed',
            '/^\sRecord created on  (.*)$/im' => 'created',
            '/^\sRecord expires on  (.*)$/im' => 'expires',
        ),
    );

    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = $contactObject->address;
                if (!is_array($filteredAddress)) {
                    $filteredAddress = explode("\n", $filteredAddress);
                }
                $firstLine = trim(array_shift($filteredAddress));
                $firstLineParts = explode(' ', $firstLine);
                $email = array_pop($firstLineParts);
                if (strpos($email, '@') !== false) {
                    $contactObject->email = $email;
                } else {
                    $firstLineParts[] = $email;
                }
                $contactObject->name = join(' ', $firstLineParts);

                $phone = trim(array_pop($filteredAddress));
                if (strpos($phone, '+') === 0) {
                    $contactObject->phone = $phone;
                } else {
                    $filteredAddress[] = $phone;
                }

                $contactObject->address = $filteredAddress;
            }
        }
    }
}
