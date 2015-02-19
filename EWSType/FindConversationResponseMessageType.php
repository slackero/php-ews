<?php
/**
 * Contains EWSType_FindConversationResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines a response to a FindConversation Operation request.
 *
 * @package php-ews\Types
 */
class EWSType_FindConversationResponseMessageType extends ResponseMessageType
{
    /**
     * Contains an array of conversations.
     *
     * @since Exchange 2010 SP1
     *
     * @var EWSType_ArrayOfConversationsType
     */
    public $Conversations;
}
