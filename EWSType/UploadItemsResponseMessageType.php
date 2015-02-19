<?php
/**
 * Contains EWSType_UploadItemsResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * the status and results of a request to upload a single mailbox item.
 *
 * @package php-ews\Types
 */
class EWSType_UploadItemsResponseMessageType extends ResponseMessageType
{
    /**
     * Contains the item identifier of an uploaded item.
     *
     * @since Exchange 2010 SP1
     *
     * @var \jamesiarmes\PEWS\Type\ItemIdType
     */
    public $ItemId;
}
