<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Botero extends Regex {

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/Nombre do Dominio:(?>[\x20\t]*)(.*?)(?=Registrante\:)/is',
        2 => '/Registrante:(?>[\x20\t]*)(.*?)(?=Contacto )/is',
        3 => '/Contacto Administrativo:(?>[\x20\t]*)(.*?)(?=Contacto Tecnico)/is',
        4 => '/Contacto Tecnico:(?>[\x20\t]*)(.*?)/is',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/Nombre de Dominio:(?>[\x20\t]*)(.*?)$/im' => 'name',
            '/Fecha de Expiracion:(?>[\x20\t]*)(.*?)$/im' => 'expires',
            '/Ultima Actualizacion:(?>[\x20\t]*)(.*?)$/im' => 'changed',
            '/Creado En:(?>[\x20\t]*)(.*?)$/im' => 'created',
            '/Nombre de Servidor:(?>[\x20\t\n]*)(.*?)\n\n/is' => 'nameserver',
        ),
        2 => array(
            '/Registrante:(.*?)(?=Correo Electronico:)/ims' => 'contacts:owner:address',
            '/Correo Electronico:(?>[\x20\t\n]*)(.*?)(?=Telefono:)/is' => 'contacts:owner:email',
            '/Telefono:(?>[\x20\t\n]*)(.*?)\n\n/is' => 'contacts:owner:phone',
        ),
        3 => array(
            '/Contacto Administrativo:(.*?)(?=Correo Electronico:)/ims' => 'contacts:admin:address',
            '/Correo Electronico:(?>[\x20\t\n]*)(.*?)(?=Telefono:)/is' => 'contacts:admin:email',
            '/Telefono:(?>[\x20\t\n]*)(.*?)\n\n/is' => 'contacts:admin:phone',
        ),
        4 => array(
            '/Contacto Tecnico:(.*?)(?=Correo Electronico:)/ims' => 'contacts:tech:address',
            '/Correo Electronico:(?>[\x20\t\n]*)(.*?)(?=Telefono:)/is' => 'contacts:tech:email',
            '/Telefono:(?>[\x20\t\n]*)(.*?)\n\n/is' => 'contacts:tech:phone',
        ),
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';

    /**
     * After parsing do something
     *
     * Fix contacts and nameservers
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));

                    foreach ($explodedAddress as $key => $line) {
                        $filteredAddress[] = trim($line);
                    }

                    $contactObject->organization = array_shift($filteredAddress);
                    $contactObject->address = $filteredAddress;

                    $filteredAddress = array();
                }

                if (stripos($contactObject->email, 'mailto:') !== false) {
                    preg_match('/mailto:([^>]*)/i', $contactObject->email, $m);
                    $contactObject->email = $m[1];
                }
            }
        }

        $dateFields = array('created', 'changed', 'expires');
        $originalDateFormat = 'd-M-Y';
        foreach ($dateFields as $field) {
            if (isset($ResultSet->$field) && strlen($ResultSet->$field)) {
                $dt = \DateTime::createFromFormat($originalDateFormat, $ResultSet->$field);
                if (is_object($dt)) {
                    $ResultSet->$field = $dt->format('Y-m-d');
                }
            }
        }
    }
}
