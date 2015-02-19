<?php
/**
 * Contains EWSType_NonEmptyArrayOfAlternateIdsType.
 */

/**
 * Defines the source identifiers to convert.
 *
 * @package php-ews\Types
 */
class EWSType_NonEmptyArrayOfAlternateIdsType extends EWSType
{
    /**
     * Describes an item or folder identifier to convert.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PEWS\Type\AlternateIdType
     */
    public $AlternateId;

    /**
     * Describes a public folder identifier to convert.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PEWS\Type\AlternatePublicFolderIdType
     */
    public $AlternatePublicFolderId;

    /**
     * Describes a public folder item identifier to convert.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PEWS\Type\AlternatePublicFolderItemIdType
     */
    public $AlternatePublicFolderItemId;
}
