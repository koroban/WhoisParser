<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Venez extends Regex {

    protected $convertFromHtml = true;

    protected $htmlBlock = '/<h3>WHOIS (.*?)<fieldset id="fieldactu">/i';

    protected $blocks = array(
        1 => '/Statut domaine: (.*?)<\/b>/im',
        2 => '/Date de cr&eacute;ation: (.*?)<\/b>/im',
        3 => '/Derni&egrave;re modification: (.*?)<\/b>/im',
        4 => '/Type: (.*?)<\/b>/im',
        5 => '/Personne: (.*?)<\/b>/im',
        6 => '/Raison sociale: (.*?)<\/b>/im',
        7 => '/Adresse &eacute;lectronique: (.*)<\/a>/im',
    );

    protected $blockItems = array(
        1 => array(
            '/<b>(.*?)<\/b>/i' => 'status',
        ),
        2 => array(
            '/<b>(.*?)<\/b>/i' => 'created',
        ),
        3 => array(
            '/<b>(.*?)<\/b>/i' => 'changed',
        ),
        4 => array(
        ),
        5 => array(
            '/<b>(.*?)<\/b>/i' => 'contacts:owner:name',
        ),
        6 => array(
            '/<b>(.*?)<\/b>/i' => 'contacts:owner:organization',
        ),
        7 => array(
            '/<a href="mailto:(.*?)">/i' => 'contacts:owner:email',
        ),
    );

    protected $available = '/Domaine non trouv&eacute;/i';


    public function postProcess(&$whoisParser)
    {
        $result = $whoisParser->getResult();

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->email = html_entity_decode($contactObject->email);
            }
        }

        $dateFields = array('created', 'changed', 'expires');
        $originalDateFormat = 'd/m/Y à H:i:s';
        foreach ($dateFields as $field) {
            if (isset($result->$field) && strlen($result->$field)) {
                $dt = \DateTime::createFromFormat($originalDateFormat, $result->$field);
                if (is_object($dt)) {
                    $result->$field = $dt->format('Y-m-d H:i:s');
                }
            }
        }
    }
}
