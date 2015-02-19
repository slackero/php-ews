<?php
/**
 * Contains EWSType_SubscribeResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single Subscribe Operation request.
 *
 * @package php-ews\Types
 */
class EWSType_SubscribeResponseMessageType extends ResponseMessageType
{
    /**
     * Represents the identifier for a subscription.
     *
     * @since Exchange 2007
     *
     * @var string
     */
    public $SubscriptionId;

    /**
     * Watermark property
     *
     * @since Exchange 2007
     *
     * @var string
     */
    public $Watermark;
}
