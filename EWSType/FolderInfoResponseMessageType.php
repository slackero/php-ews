<?php
/**
 * Contains EWSType_FolderInfoResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single CopyFolder operation request.
 *
 * @package php-ews\Types
 */
class EWSType_FolderInfoResponseMessageType extends ResponseMessageType
{
    /**
     * Contains an array of copied folders.
     *
     * @since Exchange 2007
     *
     * @var EWSType_ArrayOfFoldersType
     */
    public $Folders;
}
