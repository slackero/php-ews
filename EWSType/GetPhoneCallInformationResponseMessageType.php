<?php
/**
 * Contains EWSType_GetPhoneCallInformationResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines a response to a single GetPhoneCallInformation request.
 *
 * @package php-ews\Types
 */
class EWSType_GetPhoneCallInformationResponseMessageType extends
    ResponseMessageType
{
    /**
     * Specifies the state information for a phone call.
     *
     * @since Exchange 2010
     *
     * @var EWSType_PhoneCallInformationType
     */
    public $PhoneCallInformation;
}
