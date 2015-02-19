<?php
/**
 * Contains EWSType_PlayOnPhoneResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines the response to a request to play a voice mail over the telephone.
 *
 * @package php-ews\Types
 */
class EWSType_PlayOnPhoneResponseMessageType extends ResponseMessageType
{
    /**
     * Specifies the telephone call identifier.
     *
     * @since Exchange 2010
     *
     * @var EWSType_PhoneCallIdType
     */
    public $PhoneCallId;
}
