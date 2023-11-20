from abc import ABC

class Policy(ABC):
    """
    A policy is a set of rules that tell what actions can be done on what resources.
    """

    def from_request(self, request):
        """
        Returns a policy object from a request.
        """
        raise NotImplementedError