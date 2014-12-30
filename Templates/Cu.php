<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Cu extends Regex
{
    protected $convertFromHtml = true;

    protected $blocks = array(
        0 => '/Informaci&oacute;n general del dominio(.*?)DNS Primario/ims',
        1 => '/DNS Primario(.*?)Contacto /ims',
        2 => '/Contacto Administrativo(.*?)<td class="titletextgray">Contacto /ims',
        3 => '/Contacto T(..?|\&eacute\;)cnico(.*)<td class="titletextgray">Contacto /ims',
        4 => '/Contacto Financiero(.*)<!-- InstanceEndEditable -->/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Dominio: <\/td>\s*<td class="lowermenutextblack">(.*?)<\/td>/ims' => 'name',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Organizaci&oacute;n:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:owner:organization',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Direcci&oacute;n: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:owner:address'
        ),
        1 => array(
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Nombre: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'nameserver',
        ),
        2 => array(
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Nombre: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:admin:name',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Organizaci&oacute;n:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:admin:organization',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Direcci&oacute;n: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:admin:address',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Tel&eacute;fono:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:admin:phone',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Fax: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:admin:fax',
        ),
        3 => array(
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Nombre: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:tech:name',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Organizaci&oacute;n:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:tech:organization',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Direcci&oacute;n: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:tech:address',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Tel&eacute;fono:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:tech:phone',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Fax: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:tech:fax',
        ),
        4 => array(
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Nombre: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:billing:name',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Organizaci&oacute;n:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:billing:organization',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Direcci&oacute;n: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:billing:address',
            '/<td width="80" valign="top" class="lowermenutext(gray)?">Tel&eacute;fono:<\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:billing:phone',
            '/<td width="80" valign="top" class="lowermenutext(gray)?"> Fax: <\/td>\s*<td class="commontextblack">(.*?)<\/td>/ims' => 'contacts:billing:fax',
        )
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();
        $isRegistered = (isset($result->nameserver) && (!empty($result->nameserver)));
        $result->addItem('registered', $isRegistered);
    }
}
