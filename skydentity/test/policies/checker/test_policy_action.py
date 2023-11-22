import unittest

from skydentity.policies.checker.policy_actions import PolicyAction

class PolicyActionSuite(unittest.TestCase):
    """
    Tests the PolicyAction class.
    """

    def test_all_permission(self):
        """
        Any action should be allowed by the ALL permission.
        """
        for action in PolicyAction:
            self.assertTrue(action.is_allowed_be_performed(PolicyAction.ALL))

    def test_read_permission(self):
        """
        Given only the READ permission, only READ should be allowed.
        """
        for action in PolicyAction:
            if action == PolicyAction.READ:
                self.assertTrue(action.is_allowed_be_performed(PolicyAction.READ))
            else:
                self.assertFalse(action.is_allowed_be_performed(PolicyAction.READ))

    def test_create_permission(self):
        """
        Given only the CREATE permission, only CREATE or READ should be allowed.
        """
        for action in PolicyAction:
            if action == PolicyAction.CREATE or action == PolicyAction.READ:
                self.assertTrue(action.is_allowed_be_performed(PolicyAction.CREATE))
            else:
                self.assertFalse(action.is_allowed_be_performed(PolicyAction.CREATE))

    def test_delete_permission(self):
        """
        Given only the DELETE permission, only DELETE or READ should be allowed.
        """
        for action in PolicyAction:
            if action == PolicyAction.DELETE or action == PolicyAction.READ:
                self.assertTrue(action.is_allowed_be_performed(PolicyAction.DELETE))
            else:
                self.assertFalse(action.is_allowed_be_performed(PolicyAction.DELETE))