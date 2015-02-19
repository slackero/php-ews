<?php
/**
 * Contains EWSType_GetServiceConfigurationResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines a response to a GetServiceConfiguration request.
 *
 * @package php-ews\Types
 */
class EWSType_GetServiceConfigurationResponseMessageType extends
    ResponseMessageType
{
    /**
     * Contains an array of service configuration response messages.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ArrayOfServiceConfigurationResponseMessageType
     */
    public $ResponseMessages;
}
