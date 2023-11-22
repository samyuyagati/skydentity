import enum

class PolicyAction(enum.Enum):
    """
    An action that can be taken on a resource.
    """
    CREATE = "CREATE"
    READ = "READ"
    DELETE = "DELETE"
    ALL = "ALL"

    def is_allowed_be_performed(self, permission_action: 'PolicyAction') -> bool:
        """
        Determines whether a requested action is allowed by a permission action.
        """
        if permission_action == PolicyAction.ALL or self == permission_action:
            return True
        
        if self == PolicyAction.READ and \
            (permission_action == PolicyAction.DELETE or permission_action == PolicyAction.CREATE):
            return True
        
        return False