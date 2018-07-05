<?php namespace Nticaric\Fiskalizacija;

/**
 *
 * PHP API za fiskalizaciju računa
 *
 * @version 1.0
 * @author Nenad Tičarić <nticaric@gmail.com>
 * @project Fiskalizacija
 */

use DOMDocument;
use DOMElement;
use Exception;

class Fiskalizacija {

  public $certificate;
  private $security;
  private $url = "https://cis.porezna-uprava.hr:8449/FiskalizacijaService";

  public function __construct($path, $pass, $security = 'SSL', $demo = false) {
    if ($demo == true) {
      $this->url = "https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest";
    }
    $this->setCertificate($path, $pass);
    $this->privateKeyResource =
        openssl_pkey_get_private($this->certificate['pkey'], $pass);
    $this->publicCertificateData =
        $this->parsePublicCertData($this->certificate['cert']);
    $this->security = $security;
  }

  public function setCertificate($path, $pass)
  {
    $pkcs12 = $this->readCertificateFromDisk($path);
    openssl_pkcs12_read($pkcs12, $this->certificate, $pass);
  }

  public function readCertificateFromDisk($path)
  {
    $cert = @file_get_contents($path);
    if (false === $cert) {
      throw new \Exception("Ne mogu procitati certifikat sa lokacije: " .
        $path, 1);
    }
    return $cert;
  }

  public function getPrivateKey()
  {
    return $this->certificate['pkey'];
  }

  public function signXML($XMLRequest)
  {
    $XMLRequestDOMDoc = new DOMDocument();
    $XMLRequestDOMDoc->loadXML($XMLRequest);

    $canonical = $XMLRequestDOMDoc->C14N();
    $DigestValue = base64_encode(hash('sha1', $canonical, true));

    $rootElem = $XMLRequestDOMDoc->documentElement;

    $SignatureNode = $rootElem->appendChild(new DOMElement('Signature'));
    $SignatureNode->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

    $SignedInfoNode = $SignatureNode->appendChild(new DOMElement('SignedInfo'));
    $SignedInfoNode->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

    $CanonicalizationMethodNode = $SignedInfoNode->appendChild(new DOMElement('CanonicalizationMethod'));
    $CanonicalizationMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

    $SignatureMethodNode = $SignedInfoNode->appendChild(new DOMElement('SignatureMethod'));
    $SignatureMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');

    $ReferenceNode = $SignedInfoNode->appendChild(new DOMElement('Reference'));
    $ReferenceNode->setAttribute('URI', sprintf('#%s', $XMLRequestDOMDoc->documentElement->getAttribute('Id')));

    $TransformsNode = $ReferenceNode->appendChild(new DOMElement('Transforms'));

    $Transform1Node = $TransformsNode->appendChild(new DOMElement('Transform'));
    $Transform1Node->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');

    $Transform2Node = $TransformsNode->appendChild(new DOMElement('Transform'));
    $Transform2Node->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

    $DigestMethodNode = $ReferenceNode->appendChild(new DOMElement('DigestMethod'));
    $DigestMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');

    $ReferenceNode->appendChild(new DOMElement('DigestValue', $DigestValue));

    $SignedInfoNode = $XMLRequestDOMDoc->getElementsByTagName('SignedInfo')->item(0);

    $X509Issuer = $this->publicCertificateData['issuer'];
    $X509IssuerName = sprintf('OU=%s,O=%s,C=%s', $X509Issuer['OU'], $X509Issuer['O'], $X509Issuer['C']);
    $X509IssuerSerial = $this->publicCertificateData['serialNumber'];

    $publicCertificatePureString = str_replace('-----BEGIN CERTIFICATE-----', '', $this->certificate['cert']);
    $publicCertificatePureString = str_replace('-----END CERTIFICATE-----', '', $publicCertificatePureString);

    $this->signedInfoSignature = null;

    if (!openssl_sign($SignedInfoNode->C14N(true), $this->signedInfoSignature, $this->privateKeyResource, OPENSSL_ALGO_SHA1)) {
      throw new Exception('Unable to sign the request');
    }

    $SignatureNode = $XMLRequestDOMDoc->getElementsByTagName('Signature')->item(0);
    $SignatureValueNode = new DOMElement('SignatureValue', base64_encode($this->signedInfoSignature));
    $SignatureNode->appendChild($SignatureValueNode);

    $KeyInfoNode = $SignatureNode->appendChild(new DOMElement('KeyInfo'));

    $X509DataNode = $KeyInfoNode->appendChild(new DOMElement('X509Data'));
    $X509CertificateNode = new DOMElement('X509Certificate', $publicCertificatePureString);
    $X509DataNode->appendChild($X509CertificateNode);

    $X509IssuerSerialNode = $X509DataNode->appendChild(new DOMElement('X509IssuerSerial'));

    $X509IssuerNameNode = new DOMElement('X509IssuerName', $X509IssuerName);
    $X509IssuerSerialNode->appendChild($X509IssuerNameNode);

    $X509SerialNumberNode = new DOMElement('X509SerialNumber', $X509IssuerSerial);
    $X509IssuerSerialNode->appendChild($X509SerialNumberNode);

    $envelope = new DOMDocument();

    $envelope->loadXML('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
		  <soapenv:Body></soapenv:Body>
		</soapenv:Envelope>');

    $envelope->encoding = 'UTF-8';
    $envelope->version = '1.0';
    $XMLRequestType = $XMLRequestDOMDoc->documentElement->localName;
    $XMLRequestTypeNode = $XMLRequestDOMDoc->getElementsByTagName($XMLRequestType)->item(0);
    $XMLRequestTypeNode = $envelope->importNode($XMLRequestTypeNode, true);

    $envelope->getElementsByTagName('Body')->item(0)->appendChild($XMLRequestTypeNode);
    return $envelope->saveXML();
  }

  public function plainXML($XMLRequest)
  {
    $XMLRequestDOMDoc = new DOMDocument();
    $XMLRequestDOMDoc->loadXML($XMLRequest);

    $envelope = new DOMDocument();

    $envelope->loadXML('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
		  <soapenv:Body></soapenv:Body>
		</soapenv:Envelope>');

    $envelope->encoding = 'UTF-8';
    $envelope->version = '1.0';
    $XMLRequestType = $XMLRequestDOMDoc->documentElement->localName;
    $XMLRequestTypeNode = $XMLRequestDOMDoc->getElementsByTagName($XMLRequestType)->item(0);
    $XMLRequestTypeNode = $envelope->importNode($XMLRequestTypeNode, true);

    $envelope->getElementsByTagName('Body')->item(0)->appendChild($XMLRequestTypeNode);
    return $envelope->saveXML();
  }

  public function sendSoap($payload)
  {
    $ch = curl_init();

    $options = array(
      CURLOPT_URL => $this->url,
      CURLOPT_CONNECTTIMEOUT => 5,
      CURLOPT_TIMEOUT => 30,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $payload,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_SSL_VERIFYPEER => false,
    );

    switch ($this->security) {
      case 'SSL':
        break;
      case 'TLS':
        curl_setopt($ch, CURLOPT_SSLVERSION, 6);
        break;
      default:
        throw new \InvalidArgumentException(
          'Treći parametar konstruktora klase Fiskalizacija mora biti SSL ili TLS!'
        );
    }

    curl_setopt_array($ch, $options);

    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response) {
      curl_close($ch);
      return $this->parseResponse($response, $code);
    } else {
      throw new Exception(curl_error($ch));
      curl_close($ch);
    }

  }

  public function parseResponse($response, $code = 4)
  {
    if ($code === 200) {
      return $response;
    } else {
      $DOMResponse = new DOMDocument();
      $DOMResponse->loadXML($response);

      $SifraGreske = $DOMResponse->getElementsByTagName('SifraGreske')->item(0);
      $PorukaGreske = $DOMResponse->getElementsByTagName('PorukaGreske')->item(0);

      if ($SifraGreske && $PorukaGreske) {
        throw new Exception(sprintf('%s: %s', $SifraGreske->nodeValue, $PorukaGreske->nodeValue));
      } else {
        throw new Exception(print_r($response, true), $code);
      }
    }
  }

  private function parsePublicCertData($certPath) {
    $data = openssl_x509_parse($certPath);
    if (substr($data['serialNumber'], 0, 2) == '0x') {
      $data['serialNumber'] =
          self::convertLargeHexToDec(substr($data['serialNumber'], 2));
    }
    return $data;
  }


  private static function convertLargeHexToDec($num) {
    return self::convBase($num, '0123456789ABCDEF', '0123456789');
  }

  private static function convBase($numberInput, $fromBaseInput, $toBaseInput) {
    if ($fromBaseInput==$toBaseInput) return $numberInput;
    $fromBase = str_split($fromBaseInput,1);
    $toBase = str_split($toBaseInput,1);
    $number = str_split($numberInput,1);
    $fromLen=strlen($fromBaseInput);
    $toLen=strlen($toBaseInput);
    $numberLen=strlen($numberInput);
    $retval='';
    if ($toBaseInput == '0123456789')
    {
        $retval=0;
        for ($i = 1;$i <= $numberLen; $i++)
            $retval = bcadd(
                $retval,
                bcmul(array_search($number[$i-1], $fromBase),
                  bcpow($fromLen,$numberLen-$i)));
        return $retval;
    }
    if ($fromBaseInput != '0123456789')
        $base10 = self::convBase($numberInput, $fromBaseInput, '0123456789');
    else
        $base10 = $numberInput;
    if ($base10<strlen($toBaseInput))
        return $toBase[$base10];
    while($base10 != '0')
    {
        $retval = $toBase[bcmod($base10,$toLen)].$retval;
        $base10 = bcdiv($base10,$toLen,0);
    }
    return $retval;
  }
}
