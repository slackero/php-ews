<?php
/**
 * Contains \jamesiarmes\PEWS\Type\AlternatePublicFolderItemIdType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Describes a public folder item identifier to convert to another identifier
 * format.
 *
 * @package php-ews\Types
 */
class AlternatePublicFolderItemIdType extends AlternatePublicFolderIdType
{
    /**
     * Identifier the public folder item to convert.
     *
     * @since Exchange 2007 SP1
     *
     * @var string
     */
    public $ItemId;
}
