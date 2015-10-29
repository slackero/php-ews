<?php
/**
 * Contains NTLMSoapClient.
 */

/**
 * Soap Client using Microsoft's NTLM Authentication.
 *
 * Copyright (c) 2008 Invest-In-France Agency http://www.invest-in-france.org
 *
 * Author : Thomas Rabaix
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @link http://rabaix.net/en/articles/2008/03/13/using-soap-php-with-ntlm-authentication
 * @author Thomas Rabaix
 *
 * @package php-ews\Auth
 */
class NTLMSoapClient extends SoapClient
{
    /**
     * cURL resource used to make the SOAP request
     *
     * @var resource
     */
    protected $ch;

    /**
     * Whether or not to validate ssl certificates
     *
     * @var boolean
     */
    protected $validate = false;

    /**
     * Whether or not to check the existence of a common name in the SSL peer certificate
     *
     * @var int $verifyhost Boolean, accepts 2 (default), 1 (deprecated) or 0
     */
    protected $verifyhost = 2;

    /**
     * Whether or not to debug cUrl request and response
     *
     * @var int $debug Boolean, accepts 1 (request only), 2 (response only), 3 (request & response) or 0 (no debug)
     */
    protected $debug = 0;


    /**
     * Performs a SOAP request
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        $headers = array(
            'Method: POST',
            'Connection: Keep-Alive',
            'User-Agent: PHP-SOAP-CURL',
            'Content-Type: text/xml; charset=utf-8',
            'SOAPAction: "'.$action.'"',
        );

        $this->__last_request_headers = $headers;
        $this->ch = curl_init($location);

        // TODO: Add functionality to use COOKIE information
        //$tmp_fname = tempnam("tmp", 'COOKIE_'.$this->user);
        //curl_setopt($this->ch, CURLOPT_COOKIEJAR, $tmp_fname); //store cookie
        //curl_setopt($this->ch, CURLOPT_COOKIEFILE, $tmp_fname); //send cookie

        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, $this->validate);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, $this->validate ? $this->verifyhost : 0);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($this->ch, CURLOPT_POST, true);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, $request);
        curl_setopt($this->ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        $curl_version = curl_version();
        $curl_version = (double) $curl_version['version'];
        if($curl_version >= 7.3) {
            curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM );
        } else {
            curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC); // | CURLAUTH_NTLM — Commented NTLM for compatibility issues with curl 7.22
        }

        curl_setopt($this->ch, CURLOPT_USERPWD, $this->user.':'.$this->password);

        $response = curl_exec($this->ch);

		// TODO: Add better debug solution
		// But to get what might goes wrong when communicating
		// with the Exchange server this is enough for the moment
        if($this->debug) {
	        switch($this->debug) {
		        case 1:
					echo '<pre>';
		        	print_r(htmlspecialchars($request));
					echo '</pre>';
					break;
				case 2:
					echo '<pre>';
					print_r(htmlspecialchars($response));
					echo '</pre>';
					break;
				case 3:
					echo '<pre>';
					print_r(htmlspecialchars($request));
					print_r(htmlspecialchars($response));
					echo '</pre>';
					break;
	        }
        }

        // TODO: Add some real error handling.
        // If the response if false than there was an error and we should throw
        // an exception.
        if ($response === false) {
            throw new EWS_Exception(
              'Curl error: ' . curl_error($this->ch),
              curl_errno($this->ch)
            );
        }

        return $response;
    }

    /**
     * Returns last SOAP request headers
     *
     * @link http://php.net/manual/en/function.soap-soapclient-getlastrequestheaders.php
     *
     * @return string the last soap request headers
     */
    public function __getLastRequestHeaders()
    {
        return implode('n', $this->__last_request_headers) . "\n";
    }

    /**
     * Sets whether or not to validate ssl certificates
     *
     * @param boolean $validate
     */
    public function validateCertificate($validate = true)
    {
        $this->validate = $validate;

        return true;
    }

    /**
     * Sets whether or not to check the existence of a common name in the SSL peer certificate
     *
     * @param int $verifyhost Boolean, accepts 2 (default), 1 (deprecated) or 0
     */
    public function setVerifyHost($verifyhost = 2)
    {
    	if(!$verifyhost) {
        	$this->verifyhost = 0;
        } elseif($verifyhost !== 2) {
	        $this->verifyhost = 1; // deprecated
        } else {
	        $this->verifyhost = 2; // recommend
        }

        return true;
    }
}
