<?php
/**
 * Contains \jamesiarmes\PEWS\Type\BaseDelegateType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Base class for delegate requests.
 *
 * @package php-ews\Types
 */
abstract class BaseDelegateType extends BaserequestType
{
    /**
     * Identifies the principal's mailbox.
     *
     * @since Exchange 2007 SP1
     *
     * @var EWSType_EmailAddressType
     */
    public $Mailbox;
}
