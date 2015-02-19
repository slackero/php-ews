<?php
/**
 * Contains EWSType_GetDelegateResponseMessageType.
 */

use jamesiarmes\PEWS\Type\BaseDelegateResponseMessageType;

/**
 * Represents the status and result of a GetDelegate operation request.
 *
 * @package php-ews\Types
 */
class EWSType_GetDelegateResponseMessageType extends
    BaseDelegateResponseMessageType
{
    /**
     * Defines how meeting requests are handled between the delegate and the
     * principal.
     *
     * @since Exchange 2007 SP1
     *
     * @var EWSType_DeliverMeetingRequestsType
     */
    public $DeliverMeetingRequests;
}
