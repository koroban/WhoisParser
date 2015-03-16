<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class My extends Regex
{

    protected $blocks = array(
        0 => '/a \[(.*?)\[Invoicing Party\]/ims',
        1 => '/\[Invoicing Party\](.*?)\[Registrant Code\]/ims',
        2 => '/\[Registrant Code\](.*?)\[Administrative Contact Code\]/ims',
        3 => '/\[Administrative Contact Code\](.*?)\[Billing Contact Code\]/ims',
        4 => '/\[Billing Contact Code\](.*?)\[Technical Contact Code\]/ims',
        5 => '/\[Technical Contact Code\](.*?)\[Primary Name Server\]/ims',
        6 => '/\[Primary Name Server\](.*?)Disclaimer :/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/\[Domain Name\]\s*(.*)/im' => 'name',
            '/\[Record Created\]\s*(.*)/im' => 'created',
            '/\[Record Expired\]\s*(.*)/im' => 'expires',
            '/\[Record Last Modified\]\s*(.*)/im' => 'changed',
        ),
        1 => array(
            '/\[Invoicing Party\]\s*(.*)/im' => 'contacts:invoicing:handle',
            '/\[Invoicing Party\]\s*(.*?)\s+(.*?)\s*[a-z] \[Registrant Code\]/ims' => 'contacts:invoicing:address',
        ),
        2 => array(
            '/\[Registrant Code\]\s*(.*)/im' => 'contacts:owner:handle',
            '/\[Registrant Code\]\s*(.*?)\s+(.*?)\s*[a-z] \[Administrative Contact Code\]/ims' => 'contacts:owner:address',
        ),
        3 => array(
            '/\[Administrative Contact Code\]\s*(.*)/im' => 'contacts:admin:handle',
            '/\[Administrative Contact Code\]\s*(.*?)\s+(.*?)\s*[a-z] \[Billing Contact Code\]/ims' => 'contacts:admin:address',
        ),
        4 => array(
            '/\[Billing Contact Code\]\s*(.*)/im' => 'contacts:billing:handle',
            '/\[Billing Contact Code\]\s*(.*?)\s+(.*?)\s*[a-z] \[Technical Contact Code\]/ims' => 'contacts:billing:address',
        ),
        5 => array(
            '/\[Technical Contact Code\]\s*(.*)/im' => 'contacts:tech:handle',
            '/\[Technical Contact Code\]\s*(.*?)\s+(.*?)\s*[a-z] \[Primary Name Server\]/ims' => 'contacts:tech:address',
        ),
        6 => array(
            '/\[(Primary|Secondary) Name Server\].*?[\r\n]+(.*?)[\r\n]+/im' => 'nameserver'
        ),
    );

    protected $available = '/Domain Name \[(.+?)\] does not exist in database/im';


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));

                    $filteredAddress = array();
                    foreach ($explodedAddress as $key => $line) {
                        $line = trim($line);
                        $filteredAddress[] = $line;
                    }

                    // Deal with the first couple of lines
                    $line = array_shift($filteredAddress);
                    if (preg_match('/sdn\.? bhd/im', $line)) {
                        $contactObject->organization = $line;

                        // Check the next line for identifier in brackets
                        $line = array_shift($filteredAddress);
                        if (preg_match('/^\([^\)]+\)\s*$/', $line)) {
                            // Discard this line - I think it's like an organization incorporation number
                        } else {
                            array_unshift($filteredAddress, $line);
                        }
                    } else {
                        $contactObject->name = $line;
                        $line = array_shift($filteredAddress);
                        if (preg_match('/sdn\.? bhd/im', $line)) {
                            $contactObject->organization = $line;

                            // Check the next line for identifier in brackets
                            $line = array_shift($filteredAddress);
                            if (preg_match('/^\([^\)]+\)\s*$/', $line)) {
                                // Discard this line - I think it's like an organization incorporation number
                            } else {
                                array_unshift($filteredAddress, $line);
                            }
                        }
                    }

                    $refilteredAddress = array();
                    foreach ($filteredAddress as $key => $line) {
                        $line = trim($line);

                        $matches = array();
                        if (preg_match('/^\s*\(Tel\)(.*)$/i', $line, $matches)) {
                            // Previous line is probably email
                            if (count($refilteredAddress)) {
                                $emailLine = array_pop($refilteredAddress);
                                if (strpos($emailLine, '@') !== false) {
                                    $contactObject->email = $emailLine;
                                } else {
                                    $refilteredAddress[] = $emailLine;
                                }
                            }

                            if (count($matches[1])) {
                                $contactObject->phone = $matches[1];
                            }
                            continue;
                        } else if (preg_match('/^\s*\(Fax\)(.*)$/i', $line, $matches)) {
                            $contactObject->fax = $matches[1];
                            continue;
                        }

                        $refilteredAddress[] = trim($line);
                    }

                    $contactObject->address = $refilteredAddress;
                }
            }
        }

        // Split nameserver names from ips
        $nsNames = array();
        foreach ($result->nameserver as $ns) {
            $nsParts = explode(' ', $ns, 2);
            $nsNames[] = $nsParts[0];
        }
        $result->nameserver = $nsNames;
    }
}
