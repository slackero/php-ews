<?php
/**
 * Contains EWSType_SendNotificationResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single SendNotification operation
 * request.
 *
 * @package php-ews\Types
 */
class EWSType_SendNotificationResponseMessageType extends ResponseMessageType
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
