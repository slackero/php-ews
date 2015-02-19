<?php
/**
 * Contains EWSType_AttachmentInfoResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single CreateAttachment operation
 * request.
 *
 * @package php-ews\Types
 */
class EWSType_AttachmentInfoResponseMessageType extends ResponseMessageType
{
    /**
     * Contains the items or files that are attached to an item in the Exchange
     * store.
     *
     * @since Exchange 2007
     *
     * @var \jamesiarmes\PEWS\Type\ArrayOfAttachmentsType
     */
    public $Attachments;
}
