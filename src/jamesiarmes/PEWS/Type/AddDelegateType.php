<?php
/**
 * Contains \jamesiarmes\PEWS\Type\AddDelegateType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Defines a request to add delegates to a mailbox.
 *
 * @package php-ews\Types
 */
class AddDelegateType extends BaseDelegateType
{
    /**
     * Contains the identities of delegates to add to or update in a mailbox.
     *
     * @since Exchange 2007 SP1
     *
     * @var EWSType_ArrayOfDelegateUserType
     */
    public $DelegateUsers;

    /**
     * Defines how meeting requests are handled between the delegate and the
     * principal.
     *
     * @since Exchange 2007 SP1
     *
     * @var EWSType_DeliverMeetingRequestsType
     */
    public $DeliverMeetingRequests;
}
