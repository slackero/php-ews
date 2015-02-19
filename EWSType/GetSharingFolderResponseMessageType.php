<?php
/**
 * Contains EWSType_GetSharingFolderResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single GetSharingFolder operation
 * request.
 *
 * @package php-ews\Types
 */
class EWSType_GetSharingFolderResponseMessageType extends ResponseMessageType
{
    /**
     * Represents the identifier of the local folder in a sharing relationship.
     *
     * @since Exchange 2010
     *
     * @var EWSType_FolderIdType
     */
    public $SharingFolderId;
}
