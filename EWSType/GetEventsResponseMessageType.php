<?php
/**
 * Contains EWSType_GetEventsResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single GetEvents operation request.
 *
 * @package php-ews\Types
 */
class EWSType_GetEventsResponseMessageType extends ResponseMessageType
{
    /**
     * Contains information about the subscription and the events that have
     * occurred since the last notification.
     *
     * @since Exchange 2007
     *
     * @var EWSType_NotificationType
     */
    public $Notification;
}
